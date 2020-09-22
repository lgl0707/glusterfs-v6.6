#include <sys/vfs.h>
#include <regex.h>

#include <glusterfs/logging.h>
#include <glusterfs/run.h>
#include "rpcsvc.h"
#include "cli1-xdr.h"
#include "glusterd.h"
#include "glusterd-messages.h"
#include "glusterd-mgmt.h"
#include "glusterd-op-sm.h"
#include "glusterd-errno.h"
#include "glusterd-store.h"
#include "glusterd-utils.h"
#include "glusterd-snapshot-utils.h"
#include "glusterd-volgen.h"
#include "glusterd-syncop.h"


#define ZFS "/sbin/zfs"

char snapshot_path[VALID_GLUSTERD_PATHMAX] = ".zfs/snapshot";

struct snap_create_args_ {
    xlator_t *this;
    dict_t *dict;
    dict_t *rsp_dict;
    glusterd_volinfo_t *snap_vol;
    glusterd_brickinfo_t *brickinfo;
    struct syncargs *args;
    int32_t volcount;
    int32_t brickcount;
    int32_t brickorder;
};

typedef struct snap_create_args_ snap_create_args_t;

struct gd_snap_unsupported_opt_t {
    char *key;
    char *value;
};

char snap_mount_dir[VALID_GLUSTERD_PATHMAX];

int
glusterd_handle_zfs_snapshot_create(rpcsvc_request_t *req, glusterd_op_t op,
                                dict_t *dict, char *err_str, size_t len)
{
    int ret = -1;
    char *volname = NULL;
    char *snapname = NULL;
    int64_t volcount = 0;
    xlator_t *this = NULL;
    char key[64] = "";
    int keylen;
    char *username = NULL;
    char *password = NULL;
    uuid_t *uuid_ptr = NULL;
    uuid_t tmp_uuid = {0};
    int i = 0;
    int timestamp = 0;
    char snap_volname[GD_VOLUME_NAME_MAX] = "";
    time_t snap_time;
    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(req);
    GF_ASSERT(dict);
    GF_ASSERT(err_str);

    ret = dict_get_int64(dict, "volcount", &volcount);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "failed to "
               "get the volume count");
        goto out;
    }
    if (volcount <= 0) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
               "Invalid volume count %" PRId64 " supplied", volcount);
        ret = -1;
        goto out;
    }

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "failed to get the snapname");
        goto out;
    }

    timestamp = dict_get_str_boolean(dict, "no-timestamp", _gf_false);
    if (timestamp == -1) {
        gf_log(this->name, GF_LOG_ERROR,
               "Failed to get "
               "no-timestamp flag ");
        goto out;
    }

    ret = dict_set_int64(dict, "snap-time", (int64_t)time(&snap_time));
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Unable to set snap-time");
        goto out;
    }

    if (strlen(snapname) >= GLUSTERD_MAX_SNAP_NAME) {
        snprintf(err_str, len,
                 "snapname cannot exceed 255 "
                 "characters");
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY, "%s",
               err_str);
        ret = -1;
        goto out;
    }

    uuid_ptr = GF_MALLOC(sizeof(uuid_t), gf_common_mt_uuid_t);
    if (!uuid_ptr) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
               "Out Of Memory");
        ret = -1;
        goto out;
    }

    gf_uuid_generate(*uuid_ptr);
    ret = dict_set_bin(dict, "snap-id", uuid_ptr, sizeof(uuid_t));
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Unable to set snap-id");
        GF_FREE(uuid_ptr);
        goto out;
    }
    uuid_ptr = NULL;

    for (i = 1; i <= volcount; i++) {
        keylen = snprintf(key, sizeof(key), "volname%d", i);
        ret = dict_get_strn(dict, key, keylen, &volname);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
                   "Failed to get volume name");
            goto out;
        }

        /* generate internal username and password  for the snap*/
        gf_uuid_generate(tmp_uuid);
        username = gf_strdup(uuid_utoa(tmp_uuid));
        keylen = snprintf(key, sizeof(key), "volume%d_username", i);
        ret = dict_set_dynstrn(dict, key, keylen, username);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to set snap "
                   "username for volume %s",
                   volname);
            GF_FREE(username);
            goto out;
        }

        gf_uuid_generate(tmp_uuid);
        password = gf_strdup(uuid_utoa(tmp_uuid));
        keylen = snprintf(key, sizeof(key), "volume%d_password", i);
        ret = dict_set_dynstrn(dict, key, keylen, password);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to set snap "
                   "password for volume %s",
                   volname);
            GF_FREE(password);
            goto out;
        }

        uuid_ptr = GF_MALLOC(sizeof(uuid_t), gf_common_mt_uuid_t);
        if (!uuid_ptr) {
            gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
                   "Out Of Memory");
            ret = -1;
            goto out;
        }

        snprintf(key, sizeof(key), "vol%d_volid", i);
        gf_uuid_generate(*uuid_ptr);
        ret = dict_set_bin(dict, key, uuid_ptr, sizeof(uuid_t));
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Unable to set snap_volid");
            GF_FREE(uuid_ptr);
            goto out;
        }
        GLUSTERD_GET_UUID_NOHYPHEN(snap_volname, *uuid_ptr);
        snprintf(key, sizeof(key), "snap-volname%d", i);
        ret = dict_set_dynstr_with_alloc(dict, key, snap_volname);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Unable to set snap volname");
            GF_FREE(uuid_ptr);
            goto out;
        }
    }

    ret = glusterd_mgmt_v3_initiate_snap_phases(req, op, dict);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_INIT_FAIL,
               "Failed to initiate snap "
               "phases");
    }

out:
    return ret;
}

int32_t
glusterd_handle_zfs_snapshot_delete_type_snap(rpcsvc_request_t *req,
                                          glusterd_op_t op, dict_t *dict,
                                          char *err_str, uint32_t *op_errno,
                                          size_t len)
{
    int32_t ret = -1;
    int64_t volcount = 0;
    char *snapname = NULL;
    char *volname = NULL;
    char key[64] = "";
    int keylen;
    glusterd_snap_t *snap = NULL;
    glusterd_volinfo_t *snap_vol = NULL;
    glusterd_volinfo_t *tmp = NULL;
    xlator_t *this = NULL;

    this = THIS;
    GF_ASSERT(this);

    GF_ASSERT(req);
    GF_ASSERT(dict);
    GF_ASSERT(err_str);

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Failed to get snapname");
        goto out;
    }

    snap = glusterd_find_snap_by_name(snapname);
    if (!snap) {
        snprintf(err_str, len, "Snapshot (%s) does not exist", snapname);
        *op_errno = EG_NOSNAP;
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_NOT_FOUND, "%s",
               err_str);
        ret = -1;
        goto out;
    }

    /* Set volnames in the dict to get mgmt_v3 lock */
    cds_list_for_each_entry_safe(snap_vol, tmp, &snap->volumes, vol_list)
    {
        volcount++;
        volname = gf_strdup(snap_vol->parent_volname);
        if (!volname) {
            ret = -1;
            gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
                   "strdup failed");
            goto out;
        }

        keylen = snprintf(key, sizeof(key), "volname%" PRId64, volcount);
        ret = dict_set_dynstrn(dict, key, keylen, volname);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to set "
                   "volume name in dictionary");
            GF_FREE(volname);
            goto out;
        }
        volname = NULL;
    }

    ret = dict_set_int64(dict, "volcount", volcount);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set volcount");
        goto out;
    }

    ret = glusterd_mgmt_v3_initiate_snap_phases(req, op, dict);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_INIT_FAIL,
               "Failed to initiate snap "
               "phases");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

int
glusterd_handle_zfs_snapshot_delete(rpcsvc_request_t *req, glusterd_op_t op,
                                dict_t *dict, char *err_str, uint32_t *op_errno,
                                size_t len)
{
    int ret = -1;
    xlator_t *this = NULL;
    int32_t delete_cmd = -1;

    this = THIS;

    GF_ASSERT(this);

    GF_ASSERT(req);
    GF_ASSERT(dict);
    GF_ASSERT(err_str);
    GF_VALIDATE_OR_GOTO(this->name, op_errno, out);

    ret = dict_get_int32n(dict, "sub-cmd", SLEN("sub-cmd"), &delete_cmd);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_COMMAND_NOT_FOUND,
               "Failed to get sub-cmd");
        goto out;
    }

    switch (delete_cmd) {
        case GF_SNAP_DELETE_TYPE_SNAP:
        case GF_SNAP_DELETE_TYPE_ITER:
            ret = glusterd_handle_zfs_snapshot_delete_type_snap(
                req, op, dict, err_str, op_errno, len);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_REMOVE_FAIL,
                       "Failed to handle "
                       "snapshot delete for type SNAP");
                goto out;
            }
            break;

        case GF_SNAP_DELETE_TYPE_ALL:
            break;

        case GF_SNAP_DELETE_TYPE_VOL:
            break;

        default:
            break;
    }

    if (ret == 0 && (delete_cmd == GF_SNAP_DELETE_TYPE_ALL ||
                     delete_cmd == GF_SNAP_DELETE_TYPE_VOL)) {
        ret = glusterd_op_send_cli_response(op, 0, 0, req, dict, err_str);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_NO_CLI_RESP,
                   "Failed to send cli "
                   "response");
            goto out;
        }
    }
    ret = 0;
out:
    return ret;
}

static int
glusterd_snapshot_get_all_snapnames(dict_t *dict)
{
    int ret = -1;
    int snapcount = 0;
    char *snapname = NULL;
    char key[64] = "";
    int keylen;
    glusterd_snap_t *snap = NULL;
    glusterd_snap_t *tmp_snap = NULL;
    glusterd_conf_t *priv = NULL;
    xlator_t *this = NULL;

    this = THIS;
    priv = this->private;
    GF_ASSERT(priv);
    GF_ASSERT(dict);

    cds_list_for_each_entry_safe(snap, tmp_snap, &priv->snapshots, snap_list)
    {
        snapcount++;
        snapname = gf_strdup(snap->snapname);
        if (!snapname) {
            gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
                   "strdup failed");
            ret = -1;
            goto out;
        }
        keylen = snprintf(key, sizeof(key), "snapname%d", snapcount);
        ret = dict_set_dynstrn(dict, key, keylen, snapname);
        if (ret) {
            GF_FREE(snapname);
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to set %s", key);
            goto out;
        }
    }

    ret = dict_set_int32n(dict, "snapcount", SLEN("snapcount"), snapcount);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set snapcount");
        goto out;
    }

    ret = 0;
out:

    return ret;
}

static int
glusterd_snapshot_get_vol_snapnames(dict_t *dict, glusterd_volinfo_t *volinfo)
{
    int ret = -1;
    int snapcount = 0;
    char *snapname = NULL;
    char key[PATH_MAX] = "";
    glusterd_volinfo_t *snap_vol = NULL;
    glusterd_volinfo_t *tmp_vol = NULL;
    xlator_t *this = NULL;

    this = THIS;
    GF_ASSERT(dict);
    GF_ASSERT(volinfo);

    cds_list_for_each_entry_safe(snap_vol, tmp_vol, &volinfo->snap_volumes,
                                 snapvol_list)
    {
        snapcount++;
        snprintf(key, sizeof(key), "snapname%d", snapcount);

        ret = dict_set_dynstr_with_alloc(dict, key,
                                         snap_vol->snapshot->snapname);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to "
                   "set %s",
                   key);
            GF_FREE(snapname);
            goto out;
        }
    }

    ret = dict_set_int32n(dict, "snapcount", SLEN("snapcount"), snapcount);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set snapcount");
        goto out;
    }

    ret = 0;
out:

    return ret;
}

int
glusterd_handle_zfs_snapshot_list(rpcsvc_request_t *req, glusterd_op_t op,
                              dict_t *dict, char *err_str, size_t len,
                              uint32_t *op_errno)
{
    int ret = -1;
    char *volname = NULL;
    glusterd_volinfo_t *volinfo = NULL;
    xlator_t *this = NULL;

    this = THIS;

    GF_VALIDATE_OR_GOTO(this->name, req, out);
    GF_VALIDATE_OR_GOTO(this->name, dict, out);
    GF_VALIDATE_OR_GOTO(this->name, op_errno, out);

    /* Ignore error for getting volname as it is optional */
    ret = dict_get_strn(dict, "volname", SLEN("volname"), &volname);

    if (NULL == volname) {
        ret = glusterd_snapshot_get_all_snapnames(dict);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_LIST_GET_FAIL,
                   "Failed to get snapshot list");
            goto out;
        }
    } else {
        ret = glusterd_volinfo_find(volname, &volinfo);
        if (ret) {
            snprintf(err_str, len, "Volume (%s) does not exist", volname);
            gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_VOL_NOT_FOUND, "%s",
                   err_str);
            *op_errno = EG_NOVOL;
            goto out;
        }

        ret = glusterd_snapshot_get_vol_snapnames(dict, volinfo);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_LIST_GET_FAIL,
                   "Failed to get snapshot list for volume %s", volname);
            goto out;
        }
    }

    /* If everything is successful then send the response back to cli.
    In case of failure the caller of this function will take of response.*/
    ret = glusterd_op_send_cli_response(op, 0, 0, req, dict, err_str);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_NO_CLI_RESP,
               "Failed to send cli "
               "response");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

int
glusterd_handle_zfs_snapshot_restore(rpcsvc_request_t *req, glusterd_op_t op,
                                     dict_t *dict, char *err_str,
                                     uint32_t *op_errno, size_t len)
{
    int ret = -1;
    char *snapname = NULL;
    char *buf = NULL;
    glusterd_conf_t *conf = NULL;
    xlator_t *this = NULL;
    glusterd_snap_t *snap = NULL;
    glusterd_volinfo_t *snap_volinfo = NULL;
    int32_t i = 0;
    char key[64] = "";
    int keylen;

    this = THIS;
    GF_ASSERT(this);
    conf = this->private;

    GF_ASSERT(conf);
    GF_ASSERT(req);
    GF_ASSERT(dict);
    GF_ASSERT(err_str);

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Failed to "
               "get snapname");
        goto out;
    }

    snap = glusterd_find_snap_by_name(snapname);
    if (!snap) {
        snprintf(err_str, len, "Snapshot (%s) does not exist", snapname);
        *op_errno = EG_NOSNAP;
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_NOT_FOUND, "%s",
               err_str);
        ret = -1;
        goto out;
    }

    list_for_each_entry(snap_volinfo, &snap->volumes, vol_list)
    {
        i++;
        keylen = snprintf(key, sizeof(key), "volname%d", i);
        buf = gf_strdup(snap_volinfo->parent_volname);
        if (!buf) {
            ret = -1;
            goto out;
        }
        ret = dict_set_dynstrn(dict, key, keylen, buf);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Could not set "
                   "parent volume name %s in the dict",
                   snap_volinfo->parent_volname);
            GF_FREE(buf);
            goto out;
        }
        buf = NULL;
    }

    ret = dict_set_int32n(dict, "volcount", SLEN("volcount"), i);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Could not save volume count");
        goto out;
    }

    ret = glusterd_mgmt_v3_initiate_snap_phases(req, op, dict);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_INIT_FAIL,
               "Failed to initiate snap phases");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

static int
glusterd_zfs_snapshot_get_snapvol_detail(dict_t *dict, glusterd_volinfo_t *snap_vol,
                                     char *keyprefix, int detail)
{
    int ret = -1;
    int snap_limit = 0;
    char key[PATH_MAX] = "";
    int keylen;
    char *value = NULL;
    glusterd_volinfo_t *origin_vol = NULL;
    glusterd_conf_t *conf = NULL;
    xlator_t *this = NULL;
    uint64_t opt_hard_max = GLUSTERD_SNAPS_MAX_HARD_LIMIT;

    this = THIS;
    conf = this->private;
    GF_ASSERT(conf);

    GF_ASSERT(dict);
    GF_ASSERT(snap_vol);
    GF_ASSERT(keyprefix);

    /* Volume Name */
    value = gf_strdup(snap_vol->volname);
    if (!value)
        goto out;

    keylen = snprintf(key, sizeof(key), "%s.volname", keyprefix);
    ret = dict_set_dynstrn(dict, key, keylen, value);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set "
               "volume name in dictionary: %s",
               key);
        goto out;
    }

    /* Volume ID */
    value = gf_strdup(uuid_utoa(snap_vol->volume_id));
    if (NULL == value) {
        ret = -1;
        goto out;
    }

    keylen = snprintf(key, sizeof(key), "%s.vol-id", keyprefix);
    ret = dict_set_dynstrn(dict, key, keylen, value);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_NO_MEMORY,
               "Failed to set "
               "volume id in dictionary: %s",
               key);
        goto out;
    }
    value = NULL;

    /* volume status */
    keylen = snprintf(key, sizeof(key), "%s.vol-status", keyprefix);
    switch (snap_vol->status) {
        case GLUSTERD_STATUS_STARTED:
            ret = dict_set_nstrn(dict, key, keylen, "Started", SLEN("Started"));
            break;
        case GLUSTERD_STATUS_STOPPED:
            ret = dict_set_nstrn(dict, key, keylen, "Stopped", SLEN("Stopped"));
            break;
        case GD_SNAP_STATUS_NONE:
            ret = dict_set_nstrn(dict, key, keylen, "None", SLEN("None"));
            break;
        default:
            gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
                   "Invalid volume status");
            ret = -1;
            goto out;
    }
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set volume status"
               " in dictionary: %s",
               key);
        goto out;
    }

    ret = glusterd_volinfo_find(snap_vol->parent_volname, &origin_vol);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_VOL_NOT_FOUND,
               "failed to get the parent "
               "volinfo for the volume %s",
               snap_vol->volname);
        goto out;
    }

    /* "snap-max-hard-limit" might not be set by user explicitly,
     * in that case it's better to consider the default value.
     * Hence not erroring out if Key is not found.
     */
    ret = dict_get_uint64(conf->opts, GLUSTERD_STORE_KEY_SNAP_MAX_HARD_LIMIT,
                          &opt_hard_max);
    if (ret) {
        ret = 0;
        gf_msg_debug(this->name, 0,
                     "%s is not present in "
                     "opts dictionary",
                     GLUSTERD_STORE_KEY_SNAP_MAX_HARD_LIMIT);
    }

    if (opt_hard_max < origin_vol->snap_max_hard_limit) {
        snap_limit = opt_hard_max;
        gf_msg_debug(this->name, 0,
                     "system snap-max-hard-limit is"
                     " lesser than volume snap-max-hard-limit, "
                     "snap-max-hard-limit value is set to %d",
                     snap_limit);
    } else {
        snap_limit = origin_vol->snap_max_hard_limit;
        gf_msg_debug(this->name, 0,
                     "volume snap-max-hard-limit is"
                     " lesser than system snap-max-hard-limit, "
                     "snap-max-hard-limit value is set to %d",
                     snap_limit);
    }

    keylen = snprintf(key, sizeof(key), "%s.snaps-available", keyprefix);
    if (snap_limit > origin_vol->snap_count)
        ret = dict_set_int32n(dict, key, keylen,
                              snap_limit - origin_vol->snap_count);
    else
        ret = dict_set_int32(dict, key, 0);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set available snaps");
        goto out;
    }

    keylen = snprintf(key, sizeof(key), "%s.snapcount", keyprefix);
    ret = dict_set_int32n(dict, key, keylen, origin_vol->snap_count);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Could not save snapcount");
        goto out;
    }

    if (!detail)
        goto out;

    /* Parent volume name */
    value = gf_strdup(snap_vol->parent_volname);
    if (!value)
        goto out;

    keylen = snprintf(key, sizeof(key), "%s.origin-volname", keyprefix);
    ret = dict_set_dynstrn(dict, key, keylen, value);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set parent "
               "volume name in dictionary: %s",
               key);
        goto out;
    }
    value = NULL;

    ret = 0;
out:
    if (value)
        GF_FREE(value);

    return ret;
}

static int
glusterd_zfs_snapshot_get_snap_detail(dict_t *dict, glusterd_snap_t *snap,
                                  char *keyprefix, glusterd_volinfo_t *volinfo)
{
    int ret = -1;
    int volcount = 0;
    char key[PATH_MAX] = "";
    int keylen;
    char timestr[64] = "";
    char *value = NULL;
    glusterd_volinfo_t *snap_vol = NULL;
    glusterd_volinfo_t *tmp_vol = NULL;
    xlator_t *this = NULL;

    this = THIS;

    GF_ASSERT(dict);
    GF_ASSERT(snap);
    GF_ASSERT(keyprefix);

    /* Snap Name */
    value = gf_strdup(snap->snapname);
    if (!value)
        goto out;

    keylen = snprintf(key, sizeof(key), "%s.snapname", keyprefix);
    ret = dict_set_dynstrn(dict, key, keylen, value);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set "
               "snap name in dictionary");
        goto out;
    }

    /* Snap ID */
    value = gf_strdup(uuid_utoa(snap->snap_id));
    if (NULL == value) {
        ret = -1;
        goto out;
    }

    keylen = snprintf(key, sizeof(key), "%s.snap-id", keyprefix);
    ret = dict_set_dynstrn(dict, key, keylen, value);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set "
               "snap id in dictionary");
        goto out;
    }
    value = NULL;

    gf_time_fmt(timestr, sizeof timestr, snap->time_stamp, gf_timefmt_FT);
    value = gf_strdup(timestr);

    if (NULL == value) {
        ret = -1;
        goto out;
    }

    keylen = snprintf(key, sizeof(key), "%s.snap-time", keyprefix);
    ret = dict_set_dynstrn(dict, key, keylen, value);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set "
               "snap time stamp in dictionary");
        goto out;
    }
    value = NULL;

    /* If snap description is provided then add that into dictionary */
    if (NULL != snap->description) {
        value = gf_strdup(snap->description);
        if (NULL == value) {
            ret = -1;
            goto out;
        }

        keylen = snprintf(key, sizeof(key), "%s.snap-desc", keyprefix);
        ret = dict_set_dynstrn(dict, key, keylen, value);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to set "
                   "snap description in dictionary");
            goto out;
        }
        value = NULL;
    }

    keylen = snprintf(key, sizeof(key), "%s.snap-status", keyprefix);
    switch (snap->snap_status) {
        case GD_SNAP_STATUS_INIT:
            ret = dict_set_nstrn(dict, key, keylen, "Init", SLEN("Init"));
            break;
        case GD_SNAP_STATUS_IN_USE:
            ret = dict_set_nstrn(dict, key, keylen, "In-use", SLEN("In-use"));
            break;
        case GD_SNAP_STATUS_DECOMMISSION:
            ret = dict_set_nstrn(dict, key, keylen, "Decommisioned",
                                 SLEN("Decommisioned"));
            break;
        case GD_SNAP_STATUS_RESTORED:
            ret = dict_set_nstrn(dict, key, keylen, "Restored",
                                 SLEN("Restored"));
            break;
        case GD_SNAP_STATUS_NONE:
            ret = dict_set_nstrn(dict, key, keylen, "None", SLEN("None"));
            break;
        default:
            gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
                   "Invalid snap status");
            ret = -1;
            goto out;
    }
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set snap status "
               "in dictionary");
        goto out;
    }

    if (volinfo) {
        volcount = 1;
        snprintf(key, sizeof(key), "%s.vol%d", keyprefix, volcount);
        ret = glusterd_zfs_snapshot_get_snapvol_detail(dict, volinfo, key, 0);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_DICT_GET_FAILED,
                   "Failed to "
                   "get volume detail %s for snap %s",
                   snap_vol->volname, snap->snapname);
            goto out;
        }
        goto done;
    }

    cds_list_for_each_entry_safe(snap_vol, tmp_vol, &snap->volumes, vol_list)
    {
        volcount++;
        snprintf(key, sizeof(key), "%s.vol%d", keyprefix, volcount);
        ret = glusterd_zfs_snapshot_get_snapvol_detail(dict, snap_vol, key, 1);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
                   "Failed to "
                   "get volume detail %s for snap %s",
                   snap_vol->volname, snap->snapname);
            goto out;
        }
    }

done:
    keylen = snprintf(key, sizeof(key), "%s.vol-count", keyprefix);
    ret = dict_set_int32n(dict, key, keylen, volcount);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set %s", key);
        goto out;
    }

    ret = 0;
out:
    if (value)
        GF_FREE(value);

    return ret;
}

int
glusterd_handle_zfs_snapshot_info(rpcsvc_request_t *req, glusterd_op_t op,
                              dict_t *dict, char *err_str, size_t len)
{
    int ret = -1;
    int8_t snap_driven = 1;
    char *volname = NULL;
    char *snapname = NULL;
    glusterd_snap_t *snap = NULL;
    xlator_t *this = NULL;
    int32_t cmd = GF_SNAP_INFO_TYPE_ALL;

    this = THIS;
    GF_ASSERT(this);

    GF_VALIDATE_OR_GOTO(this->name, req, out);
    GF_VALIDATE_OR_GOTO(this->name, dict, out);

    ret = dict_get_int32n(dict, "sub-cmd", SLEN("sub-cmd"), &cmd);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Failed to get type "
               "of snapshot info");
        goto out;
    }

    switch (cmd) {
//        case GF_SNAP_INFO_TYPE_ALL: {
//            ret = glusterd_snapshot_get_all_snap_info(dict);
//            if (ret) {
//                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
//                       "Failed to get info of all snaps");
//                goto out;
//            }
//            break;
//        }

        case GF_SNAP_INFO_TYPE_SNAP: {
            ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
                       "Failed to get snap name");
                goto out;
            }

            ret = dict_set_int32n(dict, "snapcount", SLEN("snapcount"), 1);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                       "Failed to set snapcount");
                goto out;
            }

            snap = glusterd_find_snap_by_name(snapname);
            if (!snap) {
                snprintf(err_str, len, "Snapshot (%s) does not exist",
                         snapname);
                gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_NOT_FOUND,
                       "%s", err_str);
                ret = -1;
                goto out;
            }
            ret = glusterd_zfs_snapshot_get_snap_detail(dict, snap, "snap1", NULL);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_NOT_FOUND,
                       "Failed to get snap detail of snap "
                       "%s",
                       snap->snapname);
                goto out;
            }
            break;
        }

//        case GF_SNAP_INFO_TYPE_VOL: {
//            ret = dict_get_strn(dict, "volname", SLEN("volname"), &volname);
//            if (ret) {
//                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOL_NOT_FOUND,
//                       "Failed to get volname");
//                goto out;
//            }
//            ret = glusterd_snapshot_get_info_by_volume(dict, volname, err_str,
//                                                       len);
//            if (ret) {
//                gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_VOL_NOT_FOUND,
//                       "Failed to get volume info of volume "
//                       "%s",
//                       volname);
//                goto out;
//            }
//            snap_driven = 0;
//            break;
//        }
    }

    ret = dict_set_int8(dict, "snap-driven", snap_driven);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set snap-driven");
        goto out;
    }

    /* If everything is successful then send the response back to cli.
     * In case of failure the caller of this function will take care
       of the response */
    ret = glusterd_op_send_cli_response(op, 0, 0, req, dict, err_str);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_NO_CLI_RESP,
               "Failed to send cli "
               "response");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

int
glusterd_handle_zfs_snapshot_clone(rpcsvc_request_t *req, glusterd_op_t op,
                               dict_t *dict, char *err_str, size_t len)
{
    int ret = -1;
    char *clonename = NULL;
    char *snapname = NULL;
    xlator_t *this = NULL;
    char key[64] = "";
    int keylen;
    char *username = NULL;
    char *password = NULL;
    char *volname = NULL;
    uuid_t *uuid_ptr = NULL;
    uuid_t tmp_uuid = {0};
    int i = 0;
    char snap_volname[GD_VOLUME_NAME_MAX] = "";

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(req);
    GF_ASSERT(dict);
    GF_ASSERT(err_str);

    ret = dict_get_strn(dict, "clonename", SLEN("clonename"), &clonename);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "failed to "
               "get the clone name");
        goto out;
    }
    /*We need to take a volume lock on clone name*/
    volname = gf_strdup(clonename);
    keylen = snprintf(key, sizeof(key), "volname1");
    ret = dict_set_dynstrn(dict, key, keylen, volname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set clone "
               "name for volume locking");
        GF_FREE(volname);
        goto out;
    }

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "failed to get the snapname");
        goto out;
    }

    uuid_ptr = GF_MALLOC(sizeof(uuid_t), gf_common_mt_uuid_t);
    if (!uuid_ptr) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
               "Out Of Memory");
        ret = -1;
        goto out;
    }

    gf_uuid_generate(*uuid_ptr);
    ret = dict_set_bin(dict, "clone-id", uuid_ptr, sizeof(uuid_t));
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Unable to set clone-id");
        GF_FREE(uuid_ptr);
        goto out;
    }
    uuid_ptr = NULL;

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Failed to get snapname name");
        goto out;
    }

    gf_uuid_generate(tmp_uuid);
    username = gf_strdup(uuid_utoa(tmp_uuid));
    keylen = snprintf(key, sizeof(key), "volume1_username");
    ret = dict_set_dynstrn(dict, key, keylen, username);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set clone "
               "username for volume %s",
               clonename);
        GF_FREE(username);
        goto out;
    }

    gf_uuid_generate(tmp_uuid);
    password = gf_strdup(uuid_utoa(tmp_uuid));
    keylen = snprintf(key, sizeof(key), "volume1_password");
    ret = dict_set_dynstrn(dict, key, keylen, password);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set clone "
               "password for volume %s",
               clonename);
        GF_FREE(password);
        goto out;
    }

    uuid_ptr = GF_MALLOC(sizeof(uuid_t), gf_common_mt_uuid_t);
    if (!uuid_ptr) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
               "Out Of Memory");
        ret = -1;
        goto out;
    }

    snprintf(key, sizeof(key), "vol1_volid");
    gf_uuid_generate(*uuid_ptr);
    ret = dict_set_bin(dict, key, uuid_ptr, sizeof(uuid_t));
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Unable to set clone_volid");
        GF_FREE(uuid_ptr);
        goto out;
    }
    snprintf(key, sizeof(key), "clone-volname%d", i);
    ret = dict_set_dynstr_with_alloc(dict, key, snap_volname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Unable to set snap volname");
        GF_FREE(uuid_ptr);
        goto out;
    }

    ret = glusterd_mgmt_v3_initiate_snap_phases(req, op, dict);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_INIT_FAIL,
               "Failed to initiate "
               "snap phases");
    }

out:
    return ret;
}

int
glusterd_handle_zfs_snapshot_fn(rpcsvc_request_t *req)
{
    int32_t ret = 0;
    dict_t *dict = NULL;
    gf_cli_req cli_req = {
        {0},
    };
    glusterd_op_t cli_op = GD_OP_ZFS_SNAP;
    int type = 0;
    glusterd_conf_t *conf = NULL;
    char *host_uuid = NULL;
    char err_str[2048] = "";
    xlator_t *this = NULL;
    uint32_t op_errno = 0;

    GF_ASSERT(req);

    this = THIS;
    GF_ASSERT(this);
    conf = this->private;
    GF_ASSERT(conf);

    ret = xdr_to_generic(req->msg[0], &cli_req, (xdrproc_t)xdr_gf_cli_req);
    if (ret < 0) {
        req->rpc_err = GARBAGE_ARGS;
        goto out;
    }

    if (cli_req.dict.dict_len > 0) {
        dict = dict_new();
        if (!dict)
            goto out;

        ret = dict_unserialize(cli_req.dict.dict_val, cli_req.dict.dict_len,
                               &dict);
        if (ret < 0) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_UNSERIALIZE_FAIL,
                   "failed to "
                   "unserialize req-buffer to dictionary");
            snprintf(err_str, sizeof(err_str),
                     "Unable to decode "
                     "the command");
            goto out;
        }

        dict->extra_stdfree = cli_req.dict.dict_val;

        host_uuid = gf_strdup(uuid_utoa(MY_UUID));
        if (host_uuid == NULL) {
            snprintf(err_str, sizeof(err_str),
                     "Failed to get "
                     "the uuid of local glusterd");
            ret = -1;
            goto out;
        }
        ret = dict_set_dynstrn(dict, "host-uuid", SLEN("host-uuid"), host_uuid);
        if (ret) {
            GF_FREE(host_uuid);
            goto out;
        }

    } else {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
               "request dict length is %d", cli_req.dict.dict_len);
        goto out;
    }

    if (conf->op_version < GD_OP_VERSION_3_6_0) {
        snprintf(err_str, sizeof(err_str),
                 "Cluster operating version"
                 " is lesser than the supported version "
                 "for a snapshot");
        op_errno = EG_OPNOTSUP;
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_UNSUPPORTED_VERSION,
               "%s (%d < %d)", err_str, conf->op_version, GD_OP_VERSION_3_6_0);
        ret = -1;
        goto out;
    }

    ret = dict_get_int32n(dict, "type", SLEN("type"), &type);
    if (ret < 0) {
        snprintf(err_str, sizeof(err_str), "Command type not found");
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_COMMAND_NOT_FOUND, "%s",
               err_str);
        goto out;
    }

    switch (type) {
        case GF_SNAP_OPTION_TYPE_CREATE:
            ret = glusterd_handle_zfs_snapshot_create(req, cli_op, dict, err_str,
                                                  sizeof(err_str));
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_CREATION_FAIL,
                       "Snapshot create failed: %s", err_str);
            }
            break;
        case GF_SNAP_OPTION_TYPE_DELETE:
            ret = glusterd_handle_zfs_snapshot_delete(req, cli_op, dict, err_str,
                                                  &op_errno, sizeof(err_str));
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_REMOVE_FAIL,
                       "Snapshot create failed: %s", err_str);
            }
            break;

        case GF_SNAP_OPTION_TYPE_RESTORE:
            ret = glusterd_handle_zfs_snapshot_restore(req, cli_op, dict, err_str,
                                                   &op_errno, sizeof(err_str));
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_RESTORE_FAIL,
                       "Snapshot restore failed: %s", err_str);
            }
            break;

        case GF_SNAP_OPTION_TYPE_INFO:
            ret = glusterd_handle_zfs_snapshot_info(req, cli_op, dict, err_str,
                                                sizeof(err_str));
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_INFO_FAIL,
                       "Snapshot info failed");
            }
            break;

        case GF_SNAP_OPTION_TYPE_LIST:
            ret = glusterd_handle_zfs_snapshot_list(req, cli_op, dict, err_str,
                                                sizeof(err_str), &op_errno);
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_LIST_GET_FAIL,
                       "Snapshot list failed");
            }
            break;

        case GF_SNAP_OPTION_TYPE_CLONE:
            ret = glusterd_handle_zfs_snapshot_clone(req, cli_op, dict, err_str,
                                                 sizeof(err_str));
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_CLONE_FAILED,
                       "Snapshot clone "
                       "failed: %s",
                       err_str);
            }
            break;

        case GF_SNAP_OPTION_TYPE_ACTIVATE:
            ret = glusterd_mgmt_v3_initiate_snap_phases(req, cli_op, dict);
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_ACTIVATE_FAIL,
                       "Snapshot activate failed: %s", err_str);
            }
            break;
        case GF_SNAP_OPTION_TYPE_DEACTIVATE:
            ret = glusterd_mgmt_v3_initiate_snap_phases(req, cli_op, dict);
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0,
                       GD_MSG_SNAP_DEACTIVATE_FAIL,
                       "Snapshot deactivate failed: %s", err_str);
            }
            break;

        default:
            gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_COMMAND_NOT_FOUND,
                   "Unknown snapshot request "
                   "type (%d)",
                   type);
            ret = -1; /* Failure */
    }

out:
    if (ret) {
        if (err_str[0] == '\0')
            snprintf(err_str, sizeof(err_str), "Operation failed");

        if (ret && (op_errno == 0))
            op_errno = EG_INTRNL;
        ret = glusterd_op_send_cli_response(cli_op, ret, op_errno, req, dict,
                                            err_str);
    }
    return ret;
}

int
glusterd_handle_zfs_snapshot(rpcsvc_request_t *req)
{
    return glusterd_big_locked_handler(req, glusterd_handle_zfs_snapshot_fn);
}

static glusterd_snap_t *
glusterd_create_snap_object(dict_t *dict, dict_t *rsp_dict)
{
    char *snapname = NULL;
    uuid_t *snap_id = NULL;
    char *description = NULL;
    glusterd_snap_t *snap = NULL;
    xlator_t *this = NULL;
    glusterd_conf_t *priv = NULL;
    int ret = -1;
    int64_t time_stamp = 0;

    this = THIS;
    priv = this->private;

    GF_ASSERT(dict);
    GF_ASSERT(rsp_dict);

    /* Fetch snapname, description, id and time from dict */
    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch snapname");
        goto out;
    }

    /* Ignore ret value for description*/
    ret = dict_get_strn(dict, "description", SLEN("description"), &description);

    ret = dict_get_bin(dict, "snap-id", (void **)&snap_id);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch snap_id");
        goto out;
    }

    ret = dict_get_int64(dict, "snap-time", &time_stamp);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch snap-time");
        goto out;
    }
    if (time_stamp <= 0) {
        ret = -1;
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
               "Invalid time-stamp: %" PRId64, time_stamp);
        goto out;
    }

    cds_list_for_each_entry(snap, &priv->snapshots, snap_list)
    {
        if (!strcmp(snap->snapname, snapname) ||
            !gf_uuid_compare(snap->snap_id, *snap_id)) {
            gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
                   "Found duplicate snap %s (%s)", snap->snapname,
                   uuid_utoa(snap->snap_id));
            ret = -1;
            break;
        }
    }
    if (ret) {
        snap = NULL;
        goto out;
    }

    snap = glusterd_new_snap_object();
    if (!snap) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
               "Could not create "
               "the snap object for snap %s",
               snapname);
        goto out;
    }

    gf_strncpy(snap->snapname, snapname, sizeof(snap->snapname));
    gf_uuid_copy(snap->snap_id, *snap_id);
    snap->time_stamp = (time_t)time_stamp;
    /* Set the status as GD_SNAP_STATUS_INIT and once the backend snapshot
       is taken and snap is really ready to use, set the status to
       GD_SNAP_STATUS_IN_USE. This helps in identifying the incomplete
       snapshots and cleaning them up.
    */
    snap->snap_status = GD_SNAP_STATUS_INIT;
    if (description) {
        snap->description = gf_strdup(description);
        if (snap->description == NULL) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
                   "Saving the Snapshot Description Failed");
            ret = -1;
            goto out;
        }
    }

    ret = glusterd_store_snap(snap);
    if (ret) {
        gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_CREATION_FAIL,
               "Could not store snap"
               "object %s",
               snap->snapname);
        goto out;
    }

    glusterd_list_add_order(&snap->snap_list, &priv->snapshots,
                            glusterd_compare_snap_time);

    gf_msg_trace(this->name, 0, "Snapshot %s added to the list",
                 snap->snapname);

    ret = 0;

out:
    if (ret) {
        if (snap)
            glusterd_snap_remove(rsp_dict, snap, _gf_true, _gf_true, _gf_false);
        snap = NULL;
    }

    return snap;
}

static int
glusterd_snap_clear_unsupported_opt(
    glusterd_volinfo_t *volinfo,
    struct gd_snap_unsupported_opt_t *unsupported_opt)
{
    int ret = -1;
    int i = 0;

    GF_VALIDATE_OR_GOTO("glusterd", volinfo, out);

    for (i = 0; unsupported_opt[i].key; i++) {
        glusterd_volinfo_get(volinfo, unsupported_opt[i].key,
                             &unsupported_opt[i].value);

        if (unsupported_opt[i].value) {
            unsupported_opt[i].value = gf_strdup(unsupported_opt[i].value);
            if (!unsupported_opt[i].value) {
                ret = -1;
                goto out;
            }
            dict_del(volinfo->dict, unsupported_opt[i].key);
        }
    }

    ret = 0;
out:
    return ret;
}

static int
glusterd_snap_set_unsupported_opt(
    glusterd_volinfo_t *volinfo,
    struct gd_snap_unsupported_opt_t *unsupported_opt)
{
    int ret = -1;
    int i = 0;

    GF_VALIDATE_OR_GOTO("glusterd", volinfo, out);

    for (i = 0; unsupported_opt[i].key; i++) {
        if (!unsupported_opt[i].value)
            continue;

        ret = dict_set_dynstr(volinfo->dict, unsupported_opt[i].key,
                              unsupported_opt[i].value);
        if (ret) {
            gf_msg("glusterd", GF_LOG_ERROR, errno, GD_MSG_DICT_SET_FAILED,
                   "dict set failed");
            goto out;
        }
        unsupported_opt[i].value = NULL;
    }

    ret = 0;
out:
    return ret;
}

static int
file_select(const struct dirent *entry)
{
    if (entry == NULL)
        return (FALSE);

    if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0))
        return (FALSE);
    else
        return (TRUE);
}

static int32_t
glusterd_copy_geo_rep_session_files(char *session, glusterd_volinfo_t *snap_vol)
{
    int32_t ret = -1;
    char snap_session_dir[PATH_MAX] = "";
    char georep_session_dir[PATH_MAX] = "";
    regex_t *reg_exp = NULL;
    int file_count = -1;
    struct dirent **files = {
        0,
    };
    xlator_t *this = NULL;
    int i = 0;
    char src_path[PATH_MAX] = "";
    char dest_path[PATH_MAX] = "";
    glusterd_conf_t *priv = NULL;

    this = THIS;
    GF_ASSERT(this);
    priv = this->private;
    GF_ASSERT(priv);

    GF_ASSERT(session);
    GF_ASSERT(snap_vol);

    ret = snprintf(georep_session_dir, sizeof(georep_session_dir), "%s/%s/%s",
                   priv->workdir, GEOREP, session);
    if (ret < 0) { /* Negative value is an error */
        goto out;
    }

    ret = snprintf(snap_session_dir, sizeof(snap_session_dir), "%s/%s/%s/%s/%s",
                   priv->workdir, GLUSTERD_VOL_SNAP_DIR_PREFIX,
                   snap_vol->snapshot->snapname, GEOREP, session);
    if (ret < 0) { /* Negative value is an error */
        goto out;
    }

    ret = mkdir_p(snap_session_dir, 0777, _gf_true);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, errno, GD_MSG_DIR_OP_FAILED,
               "Creating directory %s failed", snap_session_dir);
        goto out;
    }

    /* TODO : good to have - Allocate in stack instead of heap */
    reg_exp = GF_CALLOC(1, sizeof(regex_t), gf_common_mt_regex_t);
    if (!reg_exp) {
        ret = -1;
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
               "Failed to allocate memory for regular expression");
        goto out;
    }

    ret = regcomp(reg_exp, "(.*status$)|(.*conf$)\0", REG_EXTENDED);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_REG_COMPILE_FAILED,
               "Failed to compile the regular expression");
        goto out;
    }

    /* If there are no files in a particular session then fail it*/
    file_count = scandir(georep_session_dir, &files, file_select, alphasort);
    if (file_count <= 0) {
        ret = -1;
        gf_msg(this->name, GF_LOG_ERROR, ENOENT, GD_MSG_FILE_OP_FAILED,
               "Session files not present "
               "in %s",
               georep_session_dir);
        goto out;
    }

    /* Now compare the file name with regular expression to see if
     * there is a match
     */
    for (i = 0; i < file_count; i++) {
        if (regexec(reg_exp, files[i]->d_name, 0, NULL, 0))
            continue;

        ret = snprintf(src_path, sizeof(src_path), "%s/%s", georep_session_dir,
                       files[i]->d_name);
        if (ret < 0) {
            goto out;
        }

        ret = snprintf(dest_path, sizeof(dest_path), "%s/%s", snap_session_dir,
                       files[i]->d_name);
        if (ret < 0) {
            goto out;
        }

        ret = glusterd_copy_file(src_path, dest_path);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
                   "Could not copy file %s of session %s", files[i]->d_name,
                   session);
            goto out;
        }
    }
out:
    /* files are malloc'd by scandir, free them */
    if (file_count > 0) {
        while (file_count--) {
            free(files[file_count]);
        }
        free(files);
    }

    if (reg_exp)
        GF_FREE(reg_exp);

    return ret;
}

static int32_t
glusterd_copy_geo_rep_files(glusterd_volinfo_t *origin_vol,
                            glusterd_volinfo_t *snap_vol, dict_t *rsp_dict)
{
    int32_t ret = -1;
    int i = 0;
    xlator_t *this = NULL;
    char key[PATH_MAX] = "";
    char session[PATH_MAX] = "";
    char slave[PATH_MAX] = "";
    char snapgeo_dir[PATH_MAX] = "";
    glusterd_conf_t *priv = NULL;

    this = THIS;
    GF_ASSERT(this);
    priv = this->private;
    GF_ASSERT(priv);

    GF_ASSERT(origin_vol);
    GF_ASSERT(snap_vol);
    GF_ASSERT(rsp_dict);

    /* This condition is not satisfied if the volume
     * is slave volume.
     */
    if (!origin_vol->gsync_slaves) {
        ret = 0;
        goto out;
    }

    GLUSTERD_GET_SNAP_GEO_REP_DIR(snapgeo_dir, snap_vol->snapshot, priv);

    ret = sys_mkdir(snapgeo_dir, 0777);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, errno, GD_MSG_DIR_OP_FAILED,
               "Creating directory %s failed", snapgeo_dir);
        goto out;
    }

    for (i = 1; i <= origin_vol->gsync_slaves->count; i++) {
        ret = snprintf(key, sizeof(key), "slave%d", i);
        if (ret < 0) /* Negative value is an error */
            goto out;

        ret = glusterd_get_geo_rep_session(
            key, origin_vol->volname, origin_vol->gsync_slaves, session, slave);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_GEOREP_GET_FAILED,
                   "Failed to get geo-rep session");
            goto out;
        }

        ret = glusterd_copy_geo_rep_session_files(session, snap_vol);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_FILE_OP_FAILED,
                   "Failed to copy files"
                   " related to session %s",
                   session);
            goto out;
        }
    }

out:
    return ret;
}

static int32_t
glusterd_add_brick_to_snap_volume(dict_t *dict, dict_t *rsp_dict,
                                  glusterd_volinfo_t *snap_vol,
                                  glusterd_brickinfo_t *original_brickinfo,
                                  int64_t volcount, int32_t brick_count,
                                  int clone)
{
    char key[64] = "";
    int keylen;
    char *value = NULL;
    char *snap_brick_dir = NULL;
    char snap_brick_path[PATH_MAX] = "";
    char clone_uuid[64] = "";
    char *snap_device = NULL;
    glusterd_brickinfo_t *snap_brickinfo = NULL;
    gf_boolean_t add_missed_snap = _gf_false;
    int32_t ret = -1;
    xlator_t *this = NULL;
    char abspath[PATH_MAX] = "";
    int32_t len = 0;
    char *snapname = NULL;

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(dict);
    GF_ASSERT(rsp_dict);
    GF_ASSERT(snap_vol);
    GF_ASSERT(original_brickinfo);

    snprintf(key, sizeof(key), "vol%" PRId64 ".origin_brickpath%d", volcount,
             brick_count);
    ret = dict_set_dynstr_with_alloc(dict, key, original_brickinfo->path);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set %s", key);
        goto out;
    }

    ret = glusterd_brickinfo_new(&snap_brickinfo);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_BRICK_NEW_INFO_FAIL,
               "initializing the brick for the snap "
               "volume failed (snapname: %s)",
               snap_vol->snapshot->snapname);
        goto out;
    }

    keylen = snprintf(key, sizeof(key), "vol%" PRId64 ".fstype%d", volcount,
                      brick_count);
    ret = dict_get_strn(dict, key, keylen, &value);
    if (!ret) {
        /* Update the fstype in original brickinfo as well */
        gf_strncpy(original_brickinfo->fstype, value,
                   sizeof(original_brickinfo->fstype));
        gf_strncpy(snap_brickinfo->fstype, value,
                   sizeof(snap_brickinfo->fstype));
    } else {
        if (is_origin_glusterd(dict) == _gf_true)
            add_missed_snap = _gf_true;
    }

    keylen = snprintf(key, sizeof(key), "vol%" PRId64 ".mnt_opts%d", volcount,
                      brick_count);
    ret = dict_get_strn(dict, key, keylen, &value);
    if (!ret) {
        /* Update the mnt_opts in original brickinfo as well */
        gf_strncpy(original_brickinfo->mnt_opts, value,
                   sizeof(original_brickinfo->mnt_opts));
        gf_strncpy(snap_brickinfo->mnt_opts, value,
                   sizeof(snap_brickinfo->mnt_opts));
    } else {
        if (is_origin_glusterd(dict) == _gf_true)
            add_missed_snap = _gf_true;
    }

    keylen = snprintf(key, sizeof(key), "vol%" PRId64 ".brickdir%d", volcount,
                      brick_count);
    ret = dict_get_strn(dict, key, keylen, &snap_brick_dir);
    if (ret) {
        /* Using original brickinfo here because it will be a
         * pending snapshot and storing the original brickinfo
         * will help in mapping while recreating the missed snapshot
         */
        gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_NOT_FOUND,
               "Unable to fetch "
               "snap mount path(%s). Adding to missed_snap_list",
               key);
        snap_brickinfo->snap_status = -1;

        snap_brick_dir = original_brickinfo->mount_dir;

        /* In origiator node add snaps missed
         * from different nodes to the dict
         */
        if (is_origin_glusterd(dict) == _gf_true)
            add_missed_snap = _gf_true;
    }

    if ((snap_brickinfo->snap_status != -1) &&
        (!gf_uuid_compare(original_brickinfo->uuid, MY_UUID)) &&
        (!glusterd_is_brick_started(original_brickinfo))) {
        /* In case if the brick goes down after prevalidate. */
        gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_BRICK_DISCONNECTED,
               "brick %s:%s is not"
               " started (snap: %s)",
               original_brickinfo->hostname, original_brickinfo->path,
               snap_vol->snapshot->snapname);

        snap_brickinfo->snap_status = -1;
        add_missed_snap = _gf_true;
    }

    if (add_missed_snap) {
        ret = glusterd_add_missed_snaps_to_dict(
            rsp_dict, snap_vol, original_brickinfo, brick_count + 1,
            GF_SNAP_OPTION_TYPE_CREATE);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_MISSEDSNAP_INFO_SET_FAIL,
                   "Failed to add missed"
                   " snapshot info for %s:%s in the rsp_dict",
                   original_brickinfo->hostname, original_brickinfo->path);
            goto out;
        }
    }

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch snapname");
        goto out;
    }

    /* Create brick-path in the format /var/run/gluster/snaps/ *
     * <snap-uuid>/<original-brick#>/snap-brick-dir *
     */
    if (clone) {
        GLUSTERD_GET_UUID_NOHYPHEN(clone_uuid, snap_vol->volume_id);
        len = snprintf(snap_brick_path, sizeof(snap_brick_path),
                       "%s/%s/brick%d%s", snap_mount_dir, clone_uuid,
                       brick_count + 1, snap_brick_dir);
    } else {
//        len = snprintf(snap_brick_path, sizeof(snap_brick_path),
//                       "%s/%s/brick%d%s", snap_mount_dir, snap_vol->volname,
//                       brick_count + 1, snap_brick_dir);
            len = snprintf(snap_brick_path, sizeof(snap_brick_path),
                           "%s/%s/%s", original_brickinfo->path, snapshot_path, snapname);
    }
    if ((len < 0) || (len >= sizeof(snap_brick_path))) {
        ret = -1;
        goto out;
    }

    keylen = snprintf(key, sizeof(key), "vol%" PRId64 ".brick_snapdevice%d",
                      volcount, brick_count);
    ret = dict_get_strn(dict, key, keylen, &snap_device);
    if (ret) {
        /* If the device name is empty, so will be the brick path
         * Hence the missed snap has already been added above
         */
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_NOT_FOUND,
               "Unable to fetch "
               "snap device (%s). Leaving empty",
               key);
    } else
        gf_strncpy(snap_brickinfo->device_path, snap_device,
                   sizeof(snap_brickinfo->device_path));

    ret = gf_canonicalize_path(snap_brick_path);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_CANONICALIZE_FAIL,
               "Failed to canonicalize path");
        goto out;
    }

    gf_strncpy(snap_brickinfo->hostname, original_brickinfo->hostname,
               sizeof(snap_brickinfo->hostname));
    gf_strncpy(snap_brickinfo->path, snap_brick_path,
               sizeof(snap_brickinfo->path));

    if (!realpath(snap_brick_path, abspath)) {
        /* ENOENT indicates that brick path has not been created which
         * is a valid scenario */
        if (errno != ENOENT) {
            gf_msg(this->name, GF_LOG_CRITICAL, errno,
                   GD_MSG_BRICKINFO_CREATE_FAIL,
                   "realpath () "
                   "failed for brick %s. The underlying filesystem"
                   " may be in bad state",
                   snap_brick_path);
            ret = -1;
            goto out;
        }
    }
    gf_strncpy(snap_brickinfo->real_path, abspath,
               sizeof(snap_brickinfo->real_path));

    gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED, "real_path：%s ", snap_brickinfo->real_path);

    gf_strncpy(snap_brickinfo->mount_dir, original_brickinfo->mount_dir,
               sizeof(snap_brickinfo->mount_dir));
    gf_uuid_copy(snap_brickinfo->uuid, original_brickinfo->uuid);
    /* AFR changelog names are based on brick_id and hence the snap
     * volume's bricks must retain the same ID */
    cds_list_add_tail(&snap_brickinfo->brick_list, &snap_vol->bricks);

    if (clone) {
        GLUSTERD_ASSIGN_BRICKID_TO_BRICKINFO(snap_brickinfo, snap_vol,
                                             brick_count);
    } else
        gf_strncpy(snap_brickinfo->brick_id, original_brickinfo->brick_id,
                   sizeof(snap_brickinfo->brick_id));

out:
    if (ret && snap_brickinfo)
        GF_FREE(snap_brickinfo);

    gf_msg_trace(this->name, 0, "Returning %d", ret);
    return ret;
}


static glusterd_volinfo_t *
glusterd_do_snap_vol(glusterd_volinfo_t *origin_vol, glusterd_snap_t *snap,
                     dict_t *dict, dict_t *rsp_dict, int64_t volcount,
                     int clone)
{
    char key[64] = "";
    int keylen;
    char *username = NULL;
    char *password = NULL;
    glusterd_brickinfo_t *brickinfo = NULL;
    glusterd_conf_t *priv = NULL;
    glusterd_volinfo_t *snap_vol = NULL;
    uuid_t *snap_volid = NULL;
    int32_t ret = -1;
    int32_t brick_count = 0;
    xlator_t *this = NULL;
    char *clonename = NULL;
    gf_boolean_t conf_present = _gf_false;
    int i = 0;

    struct gd_snap_unsupported_opt_t unsupported_opt[] = {
        {.key = VKEY_FEATURES_QUOTA, .value = NULL},
        {.key = VKEY_FEATURES_INODE_QUOTA, .value = NULL},
        {.key = "feature.deem-statfs", .value = NULL},
        {.key = "features.quota-deem-statfs", .value = NULL},
        {.key = NULL, .value = NULL}};

    this = THIS;
    GF_ASSERT(this);

    priv = this->private;
    GF_ASSERT(priv);
    GF_ASSERT(dict);
    GF_ASSERT(origin_vol);
    GF_ASSERT(rsp_dict);

    /* fetch username, password and vol_id from dict*/
    keylen = snprintf(key, sizeof(key), "volume%" PRId64 "_username", volcount);
    ret = dict_get_strn(dict, key, keylen, &username);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Failed to get %s for "
               "snap %s",
               key, snap->snapname);
        goto out;
    }
    keylen = snprintf(key, sizeof(key), "volume%" PRId64 "_password", volcount);
    ret = dict_get_strn(dict, key, keylen, &password);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Failed to get %s for "
               "snap %s",
               key, snap->snapname);
        goto out;
    }

    snprintf(key, sizeof(key), "vol%" PRId64 "_volid", volcount);
    ret = dict_get_bin(dict, key, (void **)&snap_volid);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch snap_volid");
        goto out;
    }

    /* We are not setting the username and password here as
     * we need to set the user name and password passed in
     * the dictionary
     */
    ret = glusterd_volinfo_dup(origin_vol, &snap_vol, _gf_false);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOL_OP_FAILED,
               "Failed to duplicate volinfo "
               "for the snapshot %s",
               snap->snapname);
        goto out;
    }

    /* uuid is used as lvm snapshot name.
       This will avoid restrictions on snapshot names provided by user */
    gf_uuid_copy(snap_vol->volume_id, *snap_volid);
    snap_vol->is_snap_volume = _gf_true;
    snap_vol->snapshot = snap;

    if (clone) {
        snap_vol->is_snap_volume = _gf_false;
        ret = dict_get_strn(dict, "clonename", SLEN("clonename"), &clonename);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
                   "Failed to get %s "
                   "for snap %s",
                   key, snap->snapname);
            goto out;
        }
        cds_list_add_tail(&snap_vol->vol_list, &snap->volumes);
        gf_strncpy(snap_vol->volname, clonename, sizeof(snap_vol->volname));
        gf_uuid_copy(snap_vol->restored_from_snap,
                     origin_vol->snapshot->snap_id);

    } else {
        //GLUSTERD_GET_UUID_NOHYPHEN(snap_vol->volname, *snap_volid);
        gf_strncpy(snap_vol->volname, origin_vol->volname, sizeof(snap_vol->volname));
        gf_strncpy(snap_vol->parent_volname, origin_vol->volname,
                   sizeof(snap_vol->parent_volname));
        ret = glusterd_list_add_snapvol(origin_vol, snap_vol);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_LIST_SET_FAIL,
                   "could not add the "
                   "snap volume %s to the list",
                   snap_vol->volname);
            goto out;
        }
        /* TODO : Sync before taking a snapshot */
        /* Copy the status and config files of geo-replication before
         * taking a snapshot. During restore operation these files needs
         * to be copied back in /var/lib/glusterd/georeplication/
         */
        ret = glusterd_copy_geo_rep_files(origin_vol, snap_vol, rsp_dict);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOL_OP_FAILED,
                   "Failed to copy "
                   "geo-rep config and status files for volume %s",
                   origin_vol->volname);
            goto out;
        }
    }

    glusterd_auth_set_username(snap_vol, username);
    glusterd_auth_set_password(snap_vol, password);

    /* Adding snap brickinfos to the snap volinfo */
    brick_count = 0;
    cds_list_for_each_entry(brickinfo, &origin_vol->bricks, brick_list)
    {
        ret = glusterd_add_brick_to_snap_volume(
            dict, rsp_dict, snap_vol, brickinfo, volcount, brick_count, clone);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_BRICK_ADD_FAIL,
                   "Failed to add the snap brick for "
                   "%s:%s to the snap volume",
                   brickinfo->hostname, brickinfo->path);
            goto out;
        }
        brick_count++;
    }

    /* During snapshot creation if I/O is in progress,
     * then barrier value is enabled. Hence during snapshot create
     * and in-turn snapshot restore the barrier value is set to enable.
     * Because of this further I/O on the mount point fails.
     * Hence remove the barrier key from newly created snap volinfo
     * before storing and generating the brick volfiles. Also update
     * the snap vol's version after removing the barrier key.
     */
    dict_deln(snap_vol->dict, "features.barrier", SLEN("features.barrier"));
    gd_update_volume_op_versions(snap_vol);

    ret = glusterd_store_volinfo(snap_vol, GLUSTERD_VOLINFO_VER_AC_INCREMENT);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOLINFO_SET_FAIL,
               "Failed to store snapshot "
               "volinfo (%s) for snap %s",
               snap_vol->volname, snap->snapname);
        goto out;
    }

    ret = glusterd_copy_quota_files(origin_vol, snap_vol, &conf_present);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_VOL_CONFIG_FAIL,
               "Failed to copy quota "
               "config and cksum for volume %s",
               origin_vol->volname);
        goto out;
    }

    if (snap_vol->is_snap_volume) {
        ret = glusterd_snap_clear_unsupported_opt(snap_vol, unsupported_opt);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOL_OP_FAILED,
                   "Failed to clear quota "
                   "option for the snap %s (volume: %s)",
                   snap->snapname, origin_vol->volname);
            goto out;
        }
    }

    ret = generate_brick_volfiles(snap_vol);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOLFILE_CREATE_FAIL,
               "generating the brick "
               "volfiles for the snap %s (volume: %s) failed",
               snap->snapname, origin_vol->volname);
        goto reset_option;
    }

    ret = generate_client_volfiles(snap_vol, GF_CLIENT_TRUSTED);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOLFILE_CREATE_FAIL,
               "generating the trusted "
               "client volfiles for the snap %s (volume: %s) failed",
               snap->snapname, origin_vol->volname);
        goto reset_option;
    }

    ret = generate_client_volfiles(snap_vol, GF_CLIENT_OTHER);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOLFILE_CREATE_FAIL,
               "generating the client "
               "volfiles for the snap %s (volume: %s) failed",
               snap->snapname, origin_vol->volname);
        goto reset_option;
    }

reset_option:
    if (snap_vol->is_snap_volume) {
        if (glusterd_snap_set_unsupported_opt(snap_vol, unsupported_opt)) {
            ret = -1;
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOL_OP_FAILED,
                   "Failed to reset quota "
                   "option for the snap %s (volume: %s)",
                   snap->snapname, origin_vol->volname);
        }
    }
out:
    if (ret) {
        for (i = 0; unsupported_opt[i].key; i++)
            GF_FREE(unsupported_opt[i].value);

        if (snap_vol)
            //glusterd_snap_volume_remove(rsp_dict, snap_vol, _gf_true, _gf_true);
        snap_vol = NULL;
    }

    return snap_vol;
}

int32_t
glusterd_zfs_snapshot_create_command(char *zfsname, char *snapname)
{
    //zfs snapshot device_path@snapname

    char msg[NAME_MAX] = "";
    char newsnapname[NAME_MAX] = "";
    int ret = -1;
    runner_t runner = {
        0,
    };

    snprintf(newsnapname, sizeof(msg), "%s@%s",zfsname, snapname);
    runinit(&runner);
    snprintf(msg, sizeof(msg), "zfs snapshot");
    runner_add_args(&runner, ZFS, "snapshot", newsnapname, NULL);
    runner_log(&runner, "", GF_LOG_DEBUG, msg);
    ret = runner_run(&runner);

    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
               "command create snapshot failed");
    }
    gf_msg(THIS->name, GF_LOG_ERROR, NULL, GD_MSG_INVALID_ENTRY, "finish");
    return ret;
}

static int32_t
glusterd_take_brick_zfs_snapshot(dict_t *dict, glusterd_volinfo_t *snap_vol,
                             glusterd_brickinfo_t *brickinfo, int32_t volcount,
                             int32_t brick_count, int32_t clone)
{
    char *origin_brick_path = NULL;
    char *snapname = NULL;
    char *zfsname = NULL;
    char key[64] = "";
    int keylen;
    int32_t ret = -1;
    gf_boolean_t snap_activate = _gf_false;
    xlator_t *this = NULL;
    glusterd_conf_t *priv = NULL;

    this = THIS;
    priv = this->private;
    GF_ASSERT(this);
    GF_ASSERT(dict);
    GF_ASSERT(snap_vol);
    GF_ASSERT(brickinfo);
    GF_ASSERT(priv);

//    if (strlen(brickinfo->device_path) == 0) {
//        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
//               "Device path is empty "
//               "brick %s:%s",
//               brickinfo->hostname, brickinfo->path);
//        ret = -1;
//        goto out;
//    }

    keylen = snprintf(key, sizeof(key), "vol%d.origin_brickpath%d", volcount,
                      brick_count);
    ret = dict_get_strn(dict, key, keylen, &origin_brick_path);
    if (ret) {
        gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch "
               "brick path (%s)",
               key);
        goto out;
    }

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch snapname");
        goto out;
    }

    zfsname = origin_brick_path+1;
    ret = glusterd_zfs_snapshot_create_command(zfsname, snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
               "Failed to take snapshot of "
               "brick %s:%s",
               brickinfo->hostname, origin_brick_path);
        goto out;
    }

    /* After the snapshot both the origin brick (LVM brick) and
     * the snapshot brick will have the same file-system label. This
     * will cause lot of problems at mount time. Therefore we must
     * generate a new label for the snapshot brick
     */
//    ret = glusterd_update_fs_label(brickinfo);
//    if (ret) {
//        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_FS_LABEL_UPDATE_FAIL,
//               "Failed to update "
//               "file-system label for %s brick",
//               brickinfo->path);
//        /* Failing to update label should not cause snapshot failure.
//         * Currently label is updated only for XFS and ext2/ext3/ext4
//         * file-system.
//         */
//    }

    /* create the complete brick here in case of clone and
     * activate-on-create configuration.
     */
    snap_activate = dict_get_str_boolean(
        priv->opts, GLUSTERD_STORE_KEY_SNAP_ACTIVATE, _gf_false);
    if (clone || snap_activate) {
        ret = glusterd_snap_brick_create(snap_vol, brickinfo, brick_count,
                                         clone);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_BRICK_CREATION_FAIL,
                   "not able to "
                   "create the brick for the snap %s, volume %s",
                   snap_vol->snapshot->snapname, snap_vol->volname);
            goto out;
        }
    }

out:
    gf_msg_trace(this->name, 0, "Returning %d", ret);
    return ret;
}

int
glusterd_take_brick_zfs_snapshot_task(void *opaque)
{
    int ret = 0;
    int32_t clone = 0;
    snap_create_args_t *snap_args = NULL;
    char *clonename = NULL;
    char key[64] = "";
    int keylen;

    GF_ASSERT(opaque);

    snap_args = (snap_create_args_t *)opaque;
    THIS = snap_args->this;

    /* Try and fetch clonename. If present set status with clonename *
     * else do so as snap-vol */
    ret = dict_get_strn(snap_args->dict, "clonename", SLEN("clonename"),
                        &clonename);
    if (ret) {
        keylen = snprintf(key, sizeof(key), "snap-vol%d.brick%d.status",
                          snap_args->volcount, snap_args->brickorder);
    } else {
        keylen = snprintf(key, sizeof(key), "clone%d.brick%d.status",
                          snap_args->volcount, snap_args->brickorder);
        clone = 1;
    }

    ret = glusterd_take_brick_zfs_snapshot(
        snap_args->dict, snap_args->snap_vol, snap_args->brickinfo,
        snap_args->volcount, snap_args->brickorder, clone);

    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
               "Failed to "
               "take backend snapshot for brick "
               "%s:%s volume(%s)",
               snap_args->brickinfo->hostname, snap_args->brickinfo->path,
               snap_args->snap_vol->volname);
    }

    if (dict_set_int32n(snap_args->rsp_dict, key, keylen, (ret) ? 0 : 1)) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "failed to "
               "add %s to dict",
               key);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int32_t
glusterd_take_brick_zfs_snapshot_cbk(int ret, call_frame_t *frame, void *opaque)
{
    snap_create_args_t *snap_args = NULL;
    struct syncargs *args = NULL;

    GF_ASSERT(opaque);

    snap_args = (snap_create_args_t *)opaque;
    args = snap_args->args;

    if (ret)
        args->op_ret = ret;

    GF_FREE(opaque);
    synctask_barrier_wake(args);
    return 0;
}

int32_t
glusterd_schedule_brick_zfs_snapshot(dict_t *dict, dict_t *rsp_dict,
                                 glusterd_snap_t *snap)
{
    int ret = -1;
    int32_t volcount = 0;
    int32_t brickcount = 0;
    int32_t brickorder = 0;
    int32_t taskcount = 0;
    char key[64] = "";
    int keylen;
    xlator_t *this = NULL;
    glusterd_volinfo_t *snap_vol = NULL;
    glusterd_brickinfo_t *brickinfo = NULL;
    struct syncargs args = {0};
    snap_create_args_t *snap_args = NULL;

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(dict);
    GF_ASSERT(snap);

    ret = synctask_barrier_init((&args));
    if (ret)
        goto out;
    cds_list_for_each_entry(snap_vol, &snap->volumes, vol_list)
    {
        volcount++;
        brickcount = 0;
        brickorder = 0;
        cds_list_for_each_entry(brickinfo, &snap_vol->bricks, brick_list)
        {
            keylen = snprintf(key, sizeof(key), "snap-vol%d.brick%d.order",
                              volcount, brickcount);
            ret = dict_set_int32n(rsp_dict, key, keylen, brickorder);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                       "Failed to set %s", key);
                goto out;
            }

            if ((gf_uuid_compare(brickinfo->uuid, MY_UUID)) ||
                (brickinfo->snap_status == -1)) {
                if (!gf_uuid_compare(brickinfo->uuid, MY_UUID)) {
                    brickcount++;
                    keylen = snprintf(key, sizeof(key),
                                      "snap-vol%d.brick%d.status", volcount,
                                      brickorder);
                    ret = dict_set_int32n(rsp_dict, key, keylen, 0);
                    if (ret) {
                        gf_msg(this->name, GF_LOG_ERROR, 0,
                               GD_MSG_DICT_SET_FAILED,
                               "failed to add %s to "
                               "dict",
                               key);
                        goto out;
                    }
                }
                brickorder++;
                continue;
            }

            snap_args = GF_CALLOC(1, sizeof(*snap_args),
                                  gf_gld_mt_snap_create_args_t);
            if (!snap_args) {
                ret = -1;
                goto out;
            }

            snap_args->this = this;
            snap_args->dict = dict;
            snap_args->rsp_dict = rsp_dict;
            snap_args->snap_vol = snap_vol;
            snap_args->brickinfo = brickinfo;
            snap_args->volcount = volcount;
            snap_args->brickcount = brickcount;
            snap_args->brickorder = brickorder;
            snap_args->args = &args;

            ret = synctask_new(
                this->ctx->env, glusterd_take_brick_zfs_snapshot_task,
                glusterd_take_brick_zfs_snapshot_cbk, NULL, snap_args);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
                       "Failed to "
                       "spawn task for snapshot create");
                GF_FREE(snap_args);
                goto out;
            }
            taskcount++;
            brickcount++;
            brickorder++;
        }

        snprintf(key, sizeof(key), "snap-vol%d_brickcount", volcount);
        ret = dict_set_int64(rsp_dict, key, brickcount);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "failed to "
                   "add %s to dict",
                   key);
            goto out;
        }
    }
    synctask_barrier_wait((&args), taskcount);
    taskcount = 0;

    if (args.op_ret)
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
               "Failed to create snapshot");

    ret = args.op_ret;
out:
    if (ret && taskcount)
        synctask_barrier_wait((&args), taskcount);

    return ret;
}

int32_t
glusterd_zfs_snapshot_create_commit(dict_t *dict, char **op_errstr,
                                uint32_t *op_errno, dict_t *rsp_dict)
{
    int ret = -1;
    int64_t i = 0;
    int64_t volcount = 0;
    int32_t snap_activate = 0;
    int32_t flags = 0;
    char *snapname = NULL;
    char *volname = NULL;
    char *tmp_name = NULL;
    char key[64] = "";
    int keylen;
    xlator_t *this = NULL;
    glusterd_snap_t *snap = NULL;
    glusterd_volinfo_t *origin_vol = NULL;
    glusterd_volinfo_t *snap_vol = NULL;
    glusterd_conf_t *priv = NULL;

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(dict);
    GF_ASSERT(op_errstr);
    GF_VALIDATE_OR_GOTO(this->name, op_errno, out);
    GF_ASSERT(rsp_dict);
    priv = this->private;
    GF_ASSERT(priv);

    ret = dict_get_int64(dict, "volcount", &volcount);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "failed to "
               "get the volume count");
        goto out;
    }

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch snapname");
        goto out;
    }
    tmp_name = gf_strdup(snapname);
    if (!tmp_name) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
               "Out of memory");
        ret = -1;
        goto out;
    }

    ret = dict_set_dynstr(rsp_dict, "snapname", tmp_name);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Unable to set snapname in rsp_dict");
        GF_FREE(tmp_name);
        goto out;
    }
    tmp_name = NULL;

    snap = glusterd_create_snap_object(dict, rsp_dict);
    if (!snap) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
               "creating the"
               "snap object %s failed",
               snapname);
        ret = -1;
        goto out;
    }

    for (i = 1; i <= volcount; i++) {
        keylen = snprintf(key, sizeof(key), "volname%" PRId64, i);
        ret = dict_get_strn(dict, key, keylen, &volname);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
                   "failed to get volume name");
            goto out;
        }

        ret = glusterd_volinfo_find(volname, &origin_vol);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_VOL_NOT_FOUND,
                   "failed to get the volinfo for "
                   "the volume %s",
                   volname);
            goto out;
        }

        if (is_origin_glusterd(dict)) {
            ret = glusterd_is_snap_soft_limit_reached(origin_vol, rsp_dict);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAPSHOT_OP_FAILED,
                       "Failed to "
                       "check soft limit exceeded or not, "
                       "for volume %s ",
                       origin_vol->volname);
                goto out;
            }
        }

        snap_vol = glusterd_do_snap_vol(origin_vol, snap, dict, rsp_dict, i, 0);
        if (!snap_vol) {
            ret = -1;
            gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_CREATION_FAIL,
                   "taking the "
                   "snapshot of the volume %s failed",
                   volname);
            goto out;
        }
    }
    ret = dict_set_int64(rsp_dict, "volcount", volcount);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set volcount");
        goto out;
    }

    ret = glusterd_schedule_brick_zfs_snapshot(dict, rsp_dict, snap);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
               "Failed to take backend "
               "snapshot %s",
               snap->snapname);
        goto out;
    }

    ret = dict_set_dynstr_with_alloc(rsp_dict, "snapuuid",
                                     uuid_utoa(snap->snap_id));
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set snap "
               "uuid in response dictionary for %s snapshot",
               snap->snapname);
        goto out;
    }

    snap_activate = dict_get_str_boolean(
        priv->opts, GLUSTERD_STORE_KEY_SNAP_ACTIVATE, _gf_false);
    if (!snap_activate) {
        cds_list_for_each_entry(snap_vol, &snap->volumes, vol_list)
        {
            snap_vol->status = GLUSTERD_STATUS_STOPPED;
            ret = glusterd_store_volinfo(snap_vol,
                                         GLUSTERD_VOLINFO_VER_AC_INCREMENT);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOLINFO_SET_FAIL,
                       "Failed to store snap volinfo %s", snap_vol->volname);
                goto out;
            }
        }

        goto out;
    }

    /* Activate created bricks in case of activate-on-create config. */
    ret = dict_get_int32n(dict, "flags", SLEN("flags"), &flags);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to get flags");
        goto out;
    }

    cds_list_for_each_entry(snap_vol, &snap->volumes, vol_list)
    {
        ret = glusterd_start_volume(snap_vol, flags, _gf_true);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_ACTIVATE_FAIL,
                   "Failed to activate snap volume %s of the "
                   "snap %s",
                   snap_vol->volname, snap->snapname);
            goto out;
        }
    }

    ret = 0;

out:
    if (ret) {
        if (snap)
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,"glusterd_zfs_snapshot_create_commit failed");
            //glusterd_zfs_snap_delete(rsp_dict, snap, _gf_true, _gf_true, _gf_false);
        snap = NULL;
    }

    gf_msg_trace(this->name, 0, "Returning %d", ret);
    return ret;
}

int32_t
glusterd_zfs_snapshot_delete_command(char *snapname)
{
    //zfs destroy zfsname@snapname

    char msg[NAME_MAX] = "";
    int ret = -1;
    runner_t runner = {
        0,
    };

    runinit(&runner);
    snprintf(msg, sizeof(msg), "zfs snapshot");
    runner_add_args(&runner, ZFS, "destroy", "-r", snapname, NULL);
    runner_log(&runner, "", GF_LOG_DEBUG, msg);
    ret = runner_run(&runner);

    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_REMOVE_FAIL,
               "command delete snapshot failed");
    }
    gf_msg(THIS->name, GF_LOG_ERROR, NULL, GD_MSG_INVALID_ENTRY, "delete finish");

    return ret;
}

int32_t
glusterd_zfs_snapshot_delete_task(dict_t *rsp_dict, glusterd_volinfo_t *snap_vol, int32_t volcount)
{
    int32_t brick_count = -1;
    int32_t ret = -1;
    int32_t err = 0;
    glusterd_brickinfo_t *brickinfo = NULL;
    xlator_t *this = NULL;
    char brick_dir[PATH_MAX] = "";
    char snap_path[PATH_MAX] = "";
    char *tmp = NULL;
    char *brick_mount_path = NULL;
    gf_boolean_t is_brick_dir_present = _gf_false;
    struct stat stbuf = {
        0,
    };
    char *snapname = NULL;
    char newsnapname[GLUSTERD_MAX_SNAP_NAME] = "";
    char *zfsname = NULL;
    char *origin_brick_path = NULL;
    char key[64] = "";
    int keylen;

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(snap_vol);

    if ((snap_vol->is_snap_volume == _gf_false) &&
        (gf_uuid_is_null(snap_vol->restored_from_snap))) {
        gf_msg_debug(this->name, 0,
                     "Not a snap volume, or a restored snap volume.");
        ret = 0;
        goto out;
    }

    brick_count = -1;
    cds_list_for_each_entry(brickinfo, &snap_vol->bricks, brick_list)
    {
        brick_count++;
        if (gf_uuid_compare(brickinfo->uuid, MY_UUID)) {
            gf_msg_debug(this->name, 0, "%s:%s belongs to a different node",
                         brickinfo->hostname, brickinfo->path);
            continue;
        }

        /* Fetch the brick mount path from the brickinfo->path */
//        ret = glusterd_find_brick_mount_path(brickinfo->path,
//                                             &brick_mount_path);
//        if (ret) {
//            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_BRICK_GET_INFO_FAIL,
//                   "Failed to find brick_mount_path for %s", brickinfo->path);
//            ret = 0;
//            continue;
//        }

        /* As deactivated snapshot have no active mount point we
         * check only for activated snapshot.
         */
//        if (snap_vol->status == GLUSTERD_STATUS_STARTED) {
//            ret = sys_lstat(brick_mount_path, &stbuf);
//            if (ret) {
//                gf_msg_debug(this->name, 0, "Brick %s:%s already deleted.",
//                             brickinfo->hostname, brickinfo->path);
//                ret = 0;
//                continue;
//            }
//        }

//        if (brickinfo->snap_status == -1) {
//            gf_msg(this->name, GF_LOG_INFO, 0, GD_MSG_SNAPSHOT_PENDING,
//                   "snapshot was pending. lvm not present "
//                   "for brick %s:%s of the snap %s.",
//                   brickinfo->hostname, brickinfo->path,
//                   snap_vol->snapshot->snapname);

//            if (rsp_dict && (snap_vol->is_snap_volume == _gf_true)) {
//                /* Adding missed delete to the dict */
//                ret = glusterd_add_missed_snaps_to_dict(
//                    rsp_dict, snap_vol, brickinfo, brick_count + 1,
//                    GF_SNAP_OPTION_TYPE_DELETE);
//                if (ret) {
//                    gf_msg(this->name, GF_LOG_ERROR, 0,
//                           GD_MSG_MISSED_SNAP_CREATE_FAIL,
//                           "Failed to add missed snapshot "
//                           "info for %s:%s in the "
//                           "rsp_dict",
//                           brickinfo->hostname, brickinfo->path);
//                    goto out;
//                }
//            }

//            continue;
//        }

//        /* Check if the brick has a LV associated with it */
//        if (strlen(brickinfo->device_path) == 0) {
//            gf_msg(THIS->name, GF_LOG_ERROR, NULL, GD_MSG_INVALID_ENTRY, "delete_task001");
//            gf_msg_debug(this->name, 0,
//                         "Brick (%s:%s) does not have a LV "
//                         "associated with it. Removing the brick path",
//                         brickinfo->hostname, brickinfo->path);
//            goto remove_brick_path;
//        }

//        /* Verify if the device path exists or not */
//        ret = sys_stat(brickinfo->device_path, &stbuf);
//        if (ret) {
//            gf_msg(THIS->name, GF_LOG_ERROR, NULL, GD_MSG_INVALID_ENTRY, "delete_task002");
//            gf_msg_debug(this->name, 0,
//                         "LV (%s) for brick (%s:%s) not present. "
//                         "Removing the brick path",
//                         brickinfo->device_path, brickinfo->hostname,
//                         brickinfo->path);
//            /* Making ret = 0 as absence of device path should *
//             * not fail the remove operation */
//            ret = 0;
//            goto remove_brick_path;
//        }

        ret = dict_get_strn(rsp_dict, "snapname", SLEN("snapname"), &snapname);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
                   "Unable to fetch snapname");
            goto out;
        }

        keylen = snprintf(key, sizeof(key), "vol%d.origin_brickpath%d", volcount,
                          brick_count);
        ret = dict_get_strn(rsp_dict, key, keylen, &origin_brick_path);
        zfsname = origin_brick_path+1;
        snprintf(newsnapname, sizeof(newsnapname), "%s@%s", zfsname, snapname);

        ret = glusterd_zfs_snapshot_delete_command(newsnapname);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_REMOVE_FAIL,
                   "Failed to "
                   "remove the snapshot %s (%s)",
                   brickinfo->path, brickinfo->device_path);
            err = -1; /* We need to record this failure */
        }

//        ret = glusterd_do_lvm_snapshot_remove(
//            snap_vol, brickinfo, brick_mount_path, brickinfo->device_path);
//        if (ret) {
//            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_REMOVE_FAIL,
//                   "Failed to "
//                   "remove the snapshot %s (%s)",
//                   brickinfo->path, brickinfo->device_path);
//            err = -1; /* We need to record this failure */
//        }

//    remove_brick_path:
//        /* After removing the brick dir fetch the parent path
//         * i.e /var/run/gluster/snaps/<snap-vol-id>/
//         */
//        if (is_brick_dir_present == _gf_false) {
//            /* Need to fetch brick_dir to be removed from
//             * brickinfo->path, as in a restored volume,
//             * snap_vol won't have the non-hyphenated snap_vol_id
//             */
//            tmp = strstr(brick_mount_path, "brick");
//            if (!tmp) {
//                gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
//                       "Invalid brick %s", brickinfo->path);
//                GF_FREE(brick_mount_path);
//                brick_mount_path = NULL;
//                continue;
//            }

//            strncpy(brick_dir, brick_mount_path,
//                    (size_t)(tmp - brick_mount_path));

//            /* Peers not hosting bricks will have _gf_false */
//            is_brick_dir_present = _gf_true;
//        }

//        GF_FREE(brick_mount_path);
//        brick_mount_path = NULL;
    }

//    if (is_brick_dir_present == _gf_true) {
//        ret = recursive_rmdir(brick_dir);
//        if (ret) {
//            if (errno == ENOTEMPTY) {
//                /* Will occur when multiple glusterds
//                 * are running in the same node
//                 */
//                gf_msg(this->name, GF_LOG_WARNING, errno, GD_MSG_DIR_OP_FAILED,
//                       "Failed to rmdir: %s, err: %s. "
//                       "More than one glusterd running "
//                       "on this node.",
//                       brick_dir, strerror(errno));
//                ret = 0;
//                goto out;
//            } else
//                gf_msg(this->name, GF_LOG_ERROR, errno, GD_MSG_DIR_OP_FAILED,
//                       "Failed to rmdir: %s, err: %s", brick_dir,
//                       strerror(errno));
//            goto out;
//        }

//        /* After removing brick_dir, fetch and remove snap path
//         * i.e. /var/run/gluster/snaps/<snap-name>.
//         */
//        if (!snap_vol->snapshot) {
//            gf_msg(this->name, GF_LOG_WARNING, EINVAL, GD_MSG_INVALID_ENTRY,
//                   "snapshot not"
//                   "present in snap_vol");
//            ret = -1;
//            goto out;
//        }

//        snprintf(snap_path, sizeof(snap_path), "%s/%s", snap_mount_dir,
//                 snap_vol->snapshot->snapname);
//        ret = recursive_rmdir(snap_path);
//        if (ret) {
//            gf_msg(this->name, GF_LOG_ERROR, errno, GD_MSG_DIR_OP_FAILED,
//                   "Failed to remove "
//                   "%s directory : error : %s",
//                   snap_path, strerror(errno));
//            goto out;
//        }
//    }

    ret = 0;
out:
    if (err) {
        ret = err;
    }
    GF_FREE(brick_mount_path);
    gf_msg_trace(this->name, 0, "Returning %d", ret);
    return ret;
}

int32_t
glusterd_zfs_snap_delete(dict_t *rsp_dict, glusterd_volinfo_t *snap_vol,
                            gf_boolean_t remove_lvm, gf_boolean_t force, int32_t volcount)
{
    int ret = -1;
    int save_ret = 0;
    glusterd_brickinfo_t *brickinfo = NULL;
    glusterd_volinfo_t *origin_vol = NULL;
    xlator_t *this = NULL;
    char *volname = NULL;
    int32_t brick_count = 0;
    char key[64] = "";

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(rsp_dict);
    GF_ASSERT(snap_vol);

    if (!snap_vol) {
        gf_msg(this->name, GF_LOG_WARNING, EINVAL, GD_MSG_INVALID_ENTRY,
               "snap_vol in NULL");
        ret = -1;
        goto out;
    }

    cds_list_for_each_entry(brickinfo, &snap_vol->bricks, brick_list)
    {
        if (gf_uuid_compare(brickinfo->uuid, MY_UUID))
            continue;

        ret = glusterd_brick_stop(snap_vol, brickinfo, _gf_false);
        if (ret) {
            gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_BRICK_STOP_FAIL,
                   "Failed to stop "
                   "brick for volume %s",
                   snap_vol->volname);
            save_ret = ret;

            /* Don't clean up the snap on error when
               force flag is disabled */
            if (!force)
                goto out;
        }
    }

    volname = gf_strdup(snap_vol->parent_volname);
    ret = glusterd_volinfo_find(volname, &origin_vol);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_VOL_NOT_FOUND,
               "failed to get the volinfo for "
               "the volume %s",
               volname);
        goto out;
    }
    cds_list_for_each_entry(brickinfo, &origin_vol->bricks, brick_list)
    {
        snprintf(key, sizeof(key), "vol%" PRId64 ".origin_brickpath%d", volcount,
                 brick_count);
        ret = dict_set_dynstr_with_alloc(rsp_dict, key, brickinfo->path);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to set %s", key);
            goto out;
        }
        brick_count++;
    }

    /* Only remove the backend lvm when required */
    if (remove_lvm) {
        ret = glusterd_zfs_snapshot_delete_task(rsp_dict, snap_vol, volcount);
        if (ret) {
            gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_REMOVE_FAIL,
                   "Failed to remove "
                   "lvm snapshot volume %s",
                   snap_vol->volname);
            save_ret = ret;
            if (!force)
                goto out;
        }
    }

    ret = glusterd_store_delete_volume(snap_vol);
    if (ret) {
        gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_VOL_DELETE_FAIL,
               "Failed to remove volume %s "
               "from store",
               snap_vol->volname);
        save_ret = ret;
        if (!force)
            goto out;
    }

    if (!cds_list_empty(&snap_vol->snapvol_list)) {
        ret = glusterd_volinfo_find(snap_vol->parent_volname, &origin_vol);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_VOL_NOT_FOUND,
                   "Failed to get "
                   "parent volinfo %s  for volume  %s",
                   snap_vol->parent_volname, snap_vol->volname);
            save_ret = ret;
            if (!force)
                goto out;
        }
        origin_vol->snap_count--;
    }

    glusterd_volinfo_unref(snap_vol);

    if (save_ret)
        ret = save_ret;
out:
    gf_msg_trace(this->name, 0, "returning %d", ret);
    return ret;
}

int32_t
glusterd_snap_delete(dict_t *rsp_dict, glusterd_snap_t *snap,
                     gf_boolean_t remove_lvm, gf_boolean_t force,
                     gf_boolean_t is_clone)
{
    int ret = -1;
    int save_ret = 0;
    int32_t volcount  = 0;
    glusterd_volinfo_t *snap_vol = NULL;
    glusterd_volinfo_t *tmp = NULL;
    xlator_t *this = NULL;

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(rsp_dict);
    GF_ASSERT(snap);

    if (!snap) {
        gf_msg(this->name, GF_LOG_WARNING, EINVAL, GD_MSG_INVALID_ENTRY,
               "snap is NULL");
        ret = -1;
        goto out;
    }

    cds_list_for_each_entry_safe(snap_vol, tmp, &snap->volumes, vol_list)
    {
        volcount++;
        ret = glusterd_zfs_snap_delete(rsp_dict, snap_vol, remove_lvm,
                                          force, volcount);
        if (ret && !force) {
            /* Don't clean up the snap on error when
               force flag is disabled */
            gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_REMOVE_FAIL,
                   "Failed to remove "
                   "volinfo %s for snap %s",
                   snap_vol->volname, snap->snapname);
            save_ret = ret;
            goto out;
        }
    }

    /* A clone does not persist snap info in /var/lib/glusterd/snaps/ *
     * and hence there is no snap info to be deleted from there       *
     */
    if (!is_clone) {
        ret = glusterd_store_delete_snap(snap);
        if (ret) {
            gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_REMOVE_FAIL,
                   "Failed to remove snap %s from store", snap->snapname);
            save_ret = ret;
            if (!force)
                goto out;
        }
    }

    ret = glusterd_snapobject_delete(snap);
    if (ret)
        gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_REMOVE_FAIL,
               "Failed to delete "
               "snap object %s",
               snap->snapname);

    if (save_ret)
        ret = save_ret;
out:
    gf_msg_trace(THIS->name, 0, "returning %d", ret);
    return ret;
}

int32_t
glusterd_zfs_snapshot_delete_commit(dict_t *dict, char **op_errstr,
                                dict_t *rsp_dict)
{
    int32_t ret = -1;
    char *snapname = NULL;
    char *dup_snapname = NULL;
    glusterd_snap_t *snap = NULL;
    glusterd_conf_t *priv = NULL;
    glusterd_volinfo_t *snap_volinfo = NULL;
    xlator_t *this = NULL;

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(dict);
    GF_ASSERT(rsp_dict);
    GF_ASSERT(op_errstr);

    priv = this->private;
    GF_ASSERT(priv);

    if (!dict || !op_errstr) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_INVALID_ENTRY,
               "input parameters NULL");
        goto out;
    }

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Getting the snap name "
               "failed");
        goto out;
    }

    snap = glusterd_find_snap_by_name(snapname);
    if (!snap) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_NOT_FOUND,
               "Snapshot (%s) does not exist", snapname);
        ret = -1;
        goto out;
    }

    ret = dict_set_dynstr_with_alloc(rsp_dict, "snapuuid",
                                     uuid_utoa(snap->snap_id));
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set snap uuid in "
               "response dictionary for %s snapshot",
               snap->snapname);
        goto out;
    }

    /* Save the snap status as GD_SNAP_STATUS_DECOMMISSION so
     * that if the node goes down the snap would be removed
     */
    snap->snap_status = GD_SNAP_STATUS_DECOMMISSION;
    ret = glusterd_store_snap(snap);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_OBJECT_STORE_FAIL,
               "Failed to "
               "store snap object %s",
               snap->snapname);
        goto out;
    } else
        gf_msg(this->name, GF_LOG_INFO, 0, GD_MSG_OP_SUCCESS,
               "Successfully marked "
               "snap %s for decommission.",
               snap->snapname);

//    if (is_origin_glusterd(dict) == _gf_true) {
//        /* TODO : As of now there is only volume in snapshot.
//         * Change this when multiple volume snapshot is introduced
//         */
//        snap_volinfo = cds_list_entry(snap->volumes.next, glusterd_volinfo_t,
//                                      vol_list);
//        if (!snap_volinfo) {
//            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOLINFO_GET_FAIL,
//                   "Unable to fetch snap_volinfo");
//            ret = -1;
//            goto out;
//        }

//        /* From origin glusterd check if      *
//         * any peers with snap bricks is down */
//        ret = glusterd_find_missed_snap(rsp_dict, snap_volinfo, &priv->peers,
//                                        GF_SNAP_OPTION_TYPE_DELETE);
//        if (ret) {
//            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_MISSED_SNAP_GET_FAIL,
//                   "Failed to find missed snap deletes");
//            goto out;
//        }
//    }

    ret = glusterd_snap_delete(dict, snap, _gf_true, _gf_false, _gf_false);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_REMOVE_FAIL,
               "Failed to remove snap %s", snapname);
        goto out;
    }

    dup_snapname = gf_strdup(snapname);
    if (!dup_snapname) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
               "Strdup failed");
        ret = -1;
        goto out;
    }

    ret = dict_set_dynstr(rsp_dict, "snapname", dup_snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set the snapname");
        GF_FREE(dup_snapname);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int32_t
glusterd_zfs_snap_restore_command(const char *snapname)
{
    //zfs rollback zfsname@snapname

    char msg[NAME_MAX] = "";
    int ret = -1;
    runner_t runner = {
        0,
    };

    runinit(&runner);
    snprintf(msg, sizeof(msg), "zfs snapshot");
    runner_add_args(&runner, ZFS, "rollback", "-r",snapname, NULL);
    runner_log(&runner, "", GF_LOG_DEBUG, msg);
    ret = runner_run(&runner);

    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_RESTORE_FAIL,
               "command restore snapshot failed");
    }

    return ret;
}

int32_t
glusterd_zfs_snap_restore_task(dict_t *rsp_dict, int32_t volcount, int32_t brick_count)
{
    int32_t ret = -1;
    char *snapname = NULL;
    char *origin_brick_path = NULL;
    char *zfsname = NULL;
    char newsnapname[PATH_MAX] = "";
    char key[64] = "";
    int keylen = 0;

    ret = dict_get_strn(rsp_dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch snapname");
        goto out;
    }

    keylen = snprintf(key, sizeof(key), "vol%d.origin_brickpath%d", volcount,
                      brick_count);
    ret = dict_get_strn(rsp_dict, key, keylen, &origin_brick_path);
    zfsname = origin_brick_path+1;
    snprintf(newsnapname, sizeof(newsnapname), "%s@%s", zfsname, snapname);

    ret = glusterd_zfs_snap_restore_command(newsnapname);
    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_RESTORE_FAIL,
               "restore command failed");
        goto out;
    }
    ret = 0;
out:
    return ret;
}

int32_t
glusterd_zfs_snap_restore(dict_t *rsp_dict, glusterd_snap_t *snap)
{
    glusterd_volinfo_t *snap_vol = NULL;
    glusterd_volinfo_t *tmp = NULL;
    glusterd_volinfo_t *origin_vol = NULL;
    glusterd_brickinfo_t *originbrickinfo = NULL;
    glusterd_brickinfo_t *brickinfo = NULL;
    char *volname = NULL;
    char key[64] = "";
    int32_t volcount = 0;
    int32_t brick_count = 0;
    int32_t ret = -1;

    cds_list_for_each_entry_safe(snap_vol, tmp, &snap->volumes, vol_list)
    {
        volcount++;
        volname = gf_strdup(snap_vol->parent_volname);
        ret = glusterd_volinfo_find(volname, &origin_vol);
        if (ret) {
            gf_msg(THIS->name, GF_LOG_ERROR, EINVAL, GD_MSG_VOL_NOT_FOUND,
                   "failed to get the volinfo for "
                   "the volume %s",
                   volname);
            goto out;
        }
        cds_list_for_each_entry(originbrickinfo, &origin_vol->bricks, brick_list)
        {
            snprintf(key, sizeof(key), "vol%" PRId64 ".origin_brickpath%d", volcount,
                     brick_count);
            ret = dict_set_dynstr_with_alloc(rsp_dict, key, originbrickinfo->path);
            if (ret) {
                gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                       "Failed to set %s", key);
                goto out;
            }
            brick_count++;
        }

        brick_count = -1;
        cds_list_for_each_entry(brickinfo, &snap_vol->bricks, brick_list)
        {
            brick_count++;
            if (gf_uuid_compare(brickinfo->uuid, MY_UUID)) {
                gf_msg_debug(this->name, 0, "%s:%s belongs to a different node",
                             brickinfo->hostname, brickinfo->path);
                continue;
            }
            ret = glusterd_zfs_snap_restore_task(rsp_dict, volcount, brick_count);
            if (ret) {
                gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_RESTORE_FAIL,
                       "Restore snapshot failed");
                goto out;
            }
        }
    }

    ret = 0;
out:
    return ret;
}

int32_t
glusterd_zfs_snapshot_restore_commit(dict_t *dict)
{
    int32_t ret = -1;
    char *snapname = NULL;
    glusterd_snap_t *snap = NULL;

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Getting the snap name "
               "failed");
        goto out;
    }

    snap = glusterd_find_snap_by_name(snapname);
    if (!snap) {
        gf_msg(THIS->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_NOT_FOUND,
               "Snapshot (%s) does not exist", snapname);
        ret = -1;
        goto out;
    }

    snap->snap_status = GD_SNAP_STATUS_DECOMMISSION;
    ret = glusterd_store_snap(snap);
    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_OBJECT_STORE_FAIL,
               "Failed to "
               "store snap object %s",
               snap->snapname);
        goto out;
    } else
        gf_msg(THIS->name, GF_LOG_INFO, 0, GD_MSG_OP_SUCCESS,
               "Successfully marked "
               "snap %s for decommission.",
               snap->snapname);

    ret = glusterd_zfs_snap_restore(dict, snap);
    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_RESTORE_FAIL,
               "Failed to remove snap %s", snapname);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int32_t
glusterd_zfs_snapshot_clone_command(const char *clonename, const char *snapname)
{
    //zfs clone snapname clonename

        char msg[NAME_MAX] = "";
        int ret = -1;
        runner_t runner = {
            0,
        };

        runinit(&runner);
        snprintf(msg, sizeof(msg), "zfs clone");
        runner_add_args(&runner, ZFS, "clone", snapname, clonename, NULL);
        runner_log(&runner, "", GF_LOG_DEBUG, msg);
        ret = runner_run(&runner);

        if (ret) {
            gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CLONE_FAILED,
                   "taking zfs clone failed");
        }

        return ret;
}

int32_t
glusterd_zfs_snapshot_clone_task(dict_t *rsp_dict, int32_t volcount, int32_t brick_count)
{
    int32_t ret = -1;
    char *snapname = NULL;
    char *origin_brick_path = NULL;
    char *zfsname = NULL;
    char newsnapname[PATH_MAX] = "";
    char *clonename = NULL;
    char key[64] = "";
    int keylen = 0;

    ret = dict_get_strn(rsp_dict, "clonename", SLEN("clonename"), &clonename);
    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "failed to "
               "get the clone name");
        goto out;
    }

    ret = dict_get_strn(rsp_dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch snapname");
        goto out;
    }

    keylen = snprintf(key, sizeof(key), "vol%d.origin_brickpath%d", volcount,
                      brick_count);
    ret = dict_get_strn(rsp_dict, key, keylen, &origin_brick_path);
    zfsname = origin_brick_path+1;
    snprintf(newsnapname, sizeof(newsnapname), "%s@%s", zfsname, snapname);

    ret = glusterd_zfs_snapshot_clone_command(clonename, newsnapname);
    if (ret) {
        gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_RESTORE_FAIL,
               "restore command failed");
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int32_t
glusterd_zfs_snap_clone(dict_t *rsp_dict, glusterd_snap_t *snap)
{
    glusterd_volinfo_t *snap_vol = NULL;
    glusterd_volinfo_t *tmp = NULL;
    glusterd_volinfo_t *origin_vol = NULL;
    glusterd_brickinfo_t *originbrickinfo = NULL;
    glusterd_brickinfo_t *brickinfo = NULL;
    char *volname = NULL;
    char key[64] = "";
    int32_t volcount = 0;
    int32_t brick_count = 0;
    int32_t ret = -1;

    cds_list_for_each_entry_safe(snap_vol, tmp, &snap->volumes, vol_list)
    {
        volcount++;
        volname = gf_strdup(snap_vol->parent_volname);
        ret = glusterd_volinfo_find(volname, &origin_vol);
        if (ret) {
            gf_msg(THIS->name, GF_LOG_ERROR, EINVAL, GD_MSG_VOL_NOT_FOUND,
                   "failed to get the volinfo for "
                   "the volume %s",
                   volname);
            goto out;
        }
        cds_list_for_each_entry(originbrickinfo, &origin_vol->bricks, brick_list)
        {
            snprintf(key, sizeof(key), "vol%" PRId64 ".origin_brickpath%d", volcount,
                     brick_count);
            ret = dict_set_dynstr_with_alloc(rsp_dict, key, originbrickinfo->path);
            if (ret) {
                gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                       "Failed to set %s", key);
                goto out;
            }
            brick_count++;
        }

        brick_count = -1;
        cds_list_for_each_entry(brickinfo, &snap_vol->bricks, brick_list)
        {
            brick_count++;
            ret = glusterd_zfs_snapshot_clone_task(rsp_dict, volcount, brick_count);
            if (ret) {
                gf_msg(THIS->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_RESTORE_FAIL,
                       "Restore snapshot failed");
                goto out;
            }
        }
    }

    ret = 0;
out:
    return ret;
}

static glusterd_snap_t *
glusterd_create_snap_object_for_clone(dict_t *dict, dict_t *rsp_dict)
{
    char *snapname = NULL;
    uuid_t *snap_id = NULL;
    glusterd_snap_t *snap = NULL;
    xlator_t *this = NULL;
    int ret = -1;

    this = THIS;

    GF_ASSERT(dict);
    GF_ASSERT(rsp_dict);

    /* Fetch snapname, description, id and time from dict */
    ret = dict_get_strn(dict, "clonename", SLEN("clonename"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch clonename");
        goto out;
    }

    ret = dict_get_bin(dict, "clone-id", (void **)&snap_id);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch clone_id");
        goto out;
    }

    snap = glusterd_new_snap_object();
    if (!snap) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_OBJ_NEW_FAIL,
               "Could not create "
               "the snap object for snap %s",
               snapname);
        goto out;
    }

    gf_strncpy(snap->snapname, snapname, sizeof(snap->snapname));
    gf_uuid_copy(snap->snap_id, *snap_id);

    ret = 0;

out:
    if (ret) {
        snap = NULL;
    }

    return snap;
}

int32_t
glusterd_zfs_snapshot_clone_commit(dict_t *dict, dict_t *rsp_dict)
{
    int ret = -1;
    int64_t volcount = 0;
    char *snapname = NULL;
    char *volname = NULL;
    char *tmp_name = NULL;
    xlator_t *this = NULL;
    glusterd_snap_t *snap_parent = NULL;
    glusterd_snap_t *snap = NULL;
    glusterd_volinfo_t *origin_vol = NULL;
    glusterd_volinfo_t *snap_vol = NULL;
    glusterd_conf_t *priv = NULL;

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(dict);
//    GF_ASSERT(op_errstr);
    GF_ASSERT(rsp_dict);
    priv = this->private;
    GF_ASSERT(priv);

    ret = dict_get_strn(dict, "clonename", SLEN("clonename"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to fetch clonename");
        goto out;
    }
    tmp_name = gf_strdup(snapname);
    if (!tmp_name) {
        gf_msg(this->name, GF_LOG_ERROR, ENOMEM, GD_MSG_NO_MEMORY,
               "Out of memory");
        ret = -1;
        goto out;
    }

    ret = dict_set_dynstr(rsp_dict, "clonename", tmp_name);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Unable to set clonename in rsp_dict");
        GF_FREE(tmp_name);
        goto out;
    }
    tmp_name = NULL;

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &volname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "failed to get snap name");
        goto out;
    }

    snap_parent = glusterd_find_snap_by_name(volname);
    if (!snap_parent) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_NOT_FOUND,
               "Failed to "
               "fetch snap %s",
               volname);
        goto out;
    }

    /* TODO : As of now there is only one volume in snapshot.
     * Change this when multiple volume snapshot is introduced
     */
    origin_vol = cds_list_entry(snap_parent->volumes.next, glusterd_volinfo_t,
                                vol_list);
    if (!origin_vol) {
        gf_msg("glusterd", GF_LOG_ERROR, 0, GD_MSG_VOLINFO_GET_FAIL,
               "Failed to get snap "
               "volinfo %s",
               snap_parent->snapname);
        goto out;
    }

    snap = glusterd_create_snap_object_for_clone(dict, rsp_dict);
    if (!snap) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_OBJ_NEW_FAIL,
               "creating the"
               "snap object %s failed",
               snapname);
        ret = -1;
        goto out;
    }

    snap_vol = glusterd_do_snap_vol(origin_vol, snap, dict, rsp_dict, 1, 1);
    if (!snap_vol) {
        ret = -1;
        gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_CREATION_FAIL,
               "taking the "
               "snapshot of the volume %s failed",
               volname);
        goto out;
    }

    volcount = 1;
    ret = dict_set_int64(rsp_dict, "volcount", volcount);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set volcount");
        goto out;
    }

    ret = glusterd_zfs_snap_clone(dict, snap);
    if (!snap) {
        gf_msg(THIS->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_CLONE_FAILED,
               "Failed to clone snap %s", snapname);
        ret = -1;
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int32_t
glusterd_zfs_snapshot_activate_commit(dict_t *dict, char **op_errstr,
                                  dict_t *rsp_dict)
{
    int32_t ret = -1;
    char *snapname = NULL;
    glusterd_snap_t *snap = NULL;
    glusterd_volinfo_t *snap_volinfo = NULL;
    glusterd_brickinfo_t *brickinfo = NULL;
    xlator_t *this = NULL;
    int flags = 0;
    int brick_count = -1;

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(dict);
    GF_ASSERT(rsp_dict);
    GF_ASSERT(op_errstr);

    if (!dict || !op_errstr) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_INVALID_ENTRY,
               "input parameters NULL");
        goto out;
    }

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Getting the snap name "
               "failed");
        goto out;
    }

    ret = dict_get_int32n(dict, "flags", SLEN("flags"), &flags);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to get flags");
        goto out;
    }

    snap = glusterd_find_snap_by_name(snapname);
    if (!snap) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_NOT_FOUND,
               "Snapshot (%s) does not exist", snapname);
        ret = -1;
        goto out;
    }
    /* TODO : As of now there is only volume in snapshot.
     * Change this when multiple volume snapshot is introduced
     */
    snap_volinfo = cds_list_entry(snap->volumes.next, glusterd_volinfo_t,
                                  vol_list);
    if (!snap_volinfo) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOLINFO_GET_FAIL,
               "Unable to fetch snap_volinfo");
        ret = -1;
        goto out;
    }

    /* create the complete brick here */
    cds_list_for_each_entry(brickinfo, &snap_volinfo->bricks, brick_list)
    {
        brick_count++;
        if (gf_uuid_compare(brickinfo->uuid, MY_UUID))
            continue;
//        ret = glusterd_zfs_snap_brick_create(snap_volinfo, brickinfo, brick_count,
//                                         _gf_false);
//        if (ret) {
//            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_BRICK_CREATION_FAIL,
//                   "not able to "
//                   "create the brick for the snap %s, volume %s",
//                   snap_volinfo->snapshot->snapname, snap_volinfo->volname);
//            goto out;
//        }
    }

    ret = glusterd_start_volume(snap_volinfo, flags, _gf_true);

    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_ACTIVATE_FAIL,
               "Failed to activate snap volume %s of the snap %s",
               snap_volinfo->volname, snap->snapname);
        goto out;
    }

    ret = dict_set_dynstr_with_alloc(rsp_dict, "snapuuid",
                                     uuid_utoa(snap->snap_id));
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set snap "
               "uuid in response dictionary for %s snapshot",
               snap->snapname);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int32_t
glusterd_zfs_snapshot_deactivate_commit(dict_t *dict, char **op_errstr,
                                    dict_t *rsp_dict)
{
    int32_t ret = -1;
    char *snapname = NULL;
    glusterd_snap_t *snap = NULL;
    glusterd_volinfo_t *snap_volinfo = NULL;
    xlator_t *this = NULL;
    char snap_path[PATH_MAX] = "";

    this = THIS;
    GF_ASSERT(this);
    GF_ASSERT(dict);
    GF_ASSERT(rsp_dict);
    GF_ASSERT(op_errstr);

    if (!dict || !op_errstr) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_INVALID_ENTRY,
               "input parameters NULL");
        goto out;
    }

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Getting the snap name "
               "failed");
        goto out;
    }

    snap = glusterd_find_snap_by_name(snapname);
    if (!snap) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_NOT_FOUND,
               "Snapshot (%s) does not exist", snapname);
        ret = -1;
        goto out;
    }

    /* TODO : As of now there is only volume in snapshot.
     * Change this when multiple volume snapshot is introduced
     */
    snap_volinfo = cds_list_entry(snap->volumes.next, glusterd_volinfo_t,
                                  vol_list);
    if (!snap_volinfo) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_VOLINFO_GET_FAIL,
               "Unable to fetch snap_volinfo");
        ret = -1;
        goto out;
    }

    ret = glusterd_stop_volume(snap_volinfo);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_DEACTIVATE_FAIL,
               "Failed to deactivate"
               "snap %s",
               snapname);
        goto out;
    }

    ret = glusterd_snap_unmount(this, snap_volinfo);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_GLUSTERD_UMOUNT_FAIL,
               "Failed to unmounts for %s", snap->snapname);
    }

    /*Remove /var/run/gluster/snaps/<snap-name> entry for deactivated snaps.
     * This entry will be created again during snap activate.
     */
    snprintf(snap_path, sizeof(snap_path), "%s/%s", snap_mount_dir, snapname);
    ret = recursive_rmdir(snap_path);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, errno, GD_MSG_DIR_OP_FAILED,
               "Failed to remove "
               "%s directory : error : %s",
               snap_path, strerror(errno));
        goto out;
    }

    ret = dict_set_dynstr_with_alloc(rsp_dict, "snapuuid",
                                     uuid_utoa(snap->snap_id));
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set snap "
               "uuid in response dictionary for %s snapshot",
               snap->snapname);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int
glusterd_zfs_snapshot(dict_t *dict, char **op_errstr, uint32_t *op_errno,
                      dict_t *rsp_dict)
{
    xlator_t *this = NULL;
    glusterd_conf_t *priv = NULL;
    int32_t snap_command = 0;
    char *snap_name = NULL;
    char temp[PATH_MAX] = "";
    int ret = -1;

    this = THIS;

    GF_ASSERT(this);
    GF_ASSERT(dict);
    GF_ASSERT(rsp_dict);
    GF_VALIDATE_OR_GOTO(this->name, op_errno, out);

    priv = this->private;
    GF_ASSERT(priv);

    ret = dict_get_int32n(dict, "type", SLEN("type"), &snap_command);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_COMMAND_NOT_FOUND,
               "unable to get the type of "
               "the snapshot command");
        goto out;
    }

    switch (snap_command) {
        case GF_SNAP_OPTION_TYPE_CREATE:
            ret = glusterd_zfs_snapshot_create_commit(dict, op_errstr, op_errno,
                                                  rsp_dict);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
                       "Failed to "
                       "create snapshot");
                goto out;
            }
            break;
        case GF_SNAP_OPTION_TYPE_DELETE:
            ret = glusterd_zfs_snapshot_delete_commit(dict, op_errstr, rsp_dict);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
                       "Failed to "
                       "delete snapshot");
                goto out;
            }
            break;
        case GF_SNAP_OPTION_TYPE_RESTORE:
            ret = glusterd_zfs_snapshot_restore_commit(dict);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
                       "Failed to "
                       "delete snapshot");
                goto out;
            }
            break;
        case GF_SNAP_OPTION_TYPE_CLONE:
            ret = glusterd_zfs_snapshot_clone_commit(dict, rsp_dict);
            if (ret) {
                gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_CREATION_FAIL,
                       "Failed to "
                       "delete snapshot");
                goto out;
            }
            break;

        case GF_SNAP_OPTION_TYPE_ACTIVATE:
            ret = glusterd_zfs_snapshot_activate_commit(dict, op_errstr, rsp_dict);
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_ACTIVATE_FAIL,
                       "Failed to "
                       "activate snapshot");
                goto out;
            }

            break;

        case GF_SNAP_OPTION_TYPE_DEACTIVATE:
            ret = glusterd_zfs_snapshot_deactivate_commit(dict, op_errstr,
                                                      rsp_dict);
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0,
                       GD_MSG_SNAP_DEACTIVATE_FAIL,
                       "Failed to "
                       "deactivate snapshot");
                goto out;
            }

            break;

        default:
            gf_msg(this->name, GF_LOG_WARNING, EINVAL, GD_MSG_INVALID_ENTRY,
                   "invalid snap command");
            goto out;
            break;
    }

    ret = 0;

out:
    return ret;
}

static int
glusterd_snap_create_clone_common_prevalidate(
    dict_t *rsp_dict, int flags, char *snapname, char *err_str,
    char *snap_volname, int64_t volcount, glusterd_volinfo_t *volinfo,
    gf_loglevel_t *loglevel, int clone, uint32_t *op_errno)
{
    char *device = NULL;
    char *orig_device = NULL;
    char key[PATH_MAX] = "";
    int ret = -1;
    int64_t i = 1;
    int64_t brick_order = 0;
    int64_t brick_count = 0;
    xlator_t *this = NULL;
    glusterd_conf_t *conf = NULL;
    glusterd_brickinfo_t *brickinfo = NULL;
    int32_t len = 0;

    this = THIS;
    conf = this->private;
    GF_ASSERT(conf);
    GF_VALIDATE_OR_GOTO(this->name, op_errno, out);

    if (!snapname || !volinfo) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_INVALID_ENTRY,
               "Failed to validate "
               "snapname or volume information");
        ret = -1;
        goto out;
    }

    cds_list_for_each_entry(brickinfo, &volinfo->bricks, brick_list)
    {
        if (gf_uuid_compare(brickinfo->uuid, MY_UUID)) {
            brick_order++;
            continue;
        }

//        if (!glusterd_is_brick_started(brickinfo)) {
//            if (!clone && (flags & GF_CLI_FLAG_OP_FORCE)) {
//                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_BRICK_DISCONNECTED,
//                       "brick %s:%s is not started", brickinfo->hostname,
//                       brickinfo->path);
//                brick_order++;
//                brick_count++;
//                continue;
//            }
//            if (!clone) {
//                snprintf(err_str, PATH_MAX,
//                         "One or more bricks are not running. "
//                         "Please run volume status command to see "
//                         "brick status.\n"
//                         "Please start the stopped brick "
//                         "and then issue snapshot create "
//                         "command or use [force] option in "
//                         "snapshot create to override this "
//                         "behavior.");
//            } else {
//                snprintf(err_str, PATH_MAX,
//                         "One or more bricks are not running. "
//                         "Please run snapshot status command to see "
//                         "brick status.\n"
//                         "Please start the stopped brick "
//                         "and then issue snapshot clone "
//                         "command ");
//            }
//            *op_errno = EG_BRCKDWN;
//            ret = -1;
//            goto out;
//        }

//        orig_device = glusterd_get_brick_mount_device(brickinfo->path);
//        if (!orig_device) {
//            len = snprintf(err_str, PATH_MAX,
//                           "getting device name for the brick "
//                           "%s:%s failed",
//                           brickinfo->hostname, brickinfo->path);
//            if (len < 0) {
//                strcpy(err_str, "<error>");
//            }
//            ret = -1;
//            goto out;
//        }
//        if (!clone) {
//            if (!glusterd_is_thinp_brick(orig_device, op_errno)) {
//                snprintf(err_str, PATH_MAX,
//                         "Snapshot is supported only for "
//                         "thin provisioned LV. Ensure that "
//                         "all bricks of %s are thinly "
//                         "provisioned LV.",
//                         volinfo->volname);
//                ret = -1;
//                goto out;
//            }
//        }

//        device = glusterd_build_snap_device_path(orig_device, snap_volname,
//                                                 brick_count);
//        if (!device) {
//            snprintf(err_str, PATH_MAX,
//                     "cannot copy the snapshot device "
//                     "name (volname: %s, snapname: %s)",
//                     volinfo->volname, snapname);
//            *loglevel = GF_LOG_WARNING;
//            ret = -1;
//            goto out;
//        }

//        GF_FREE(orig_device);
//        orig_device = NULL;

//        snprintf(key, sizeof(key), "vol%" PRId64 ".brick_snapdevice%" PRId64, i,
//                 brick_count);
//        ret = dict_set_dynstr_with_alloc(rsp_dict, key, device);
//        if (ret) {
//            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
//                   "Failed to set %s", key);
//            goto out;
//        }

        ret = glusterd_update_mntopts(brickinfo->path, brickinfo);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_BRK_MOUNTOPTS_FAIL,
                   "Failed to "
                   "update mount options for %s brick",
                   brickinfo->path);
        }

        snprintf(key, sizeof(key), "vol%" PRId64 ".fstype%" PRId64, i,
                 brick_count);
        ret = dict_set_dynstr_with_alloc(rsp_dict, key, brickinfo->fstype);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to set %s", key);
            goto out;
        }

        snprintf(key, sizeof(key), "vol%" PRId64 ".mnt_opts%" PRId64, i,
                 brick_count);
        ret = dict_set_dynstr_with_alloc(rsp_dict, key, brickinfo->mnt_opts);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to set %s", key);
            goto out;
        }

        snprintf(key, sizeof(key), "vol%" PRId64 ".brickdir%" PRId64, i,
                 brick_count);
        ret = dict_set_dynstr_with_alloc(rsp_dict, key, brickinfo->mount_dir);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to set %s", key);
            goto out;
        }

        snprintf(key, sizeof(key) - 1, "vol%" PRId64 ".brick%" PRId64 ".order",
                 i, brick_count);
        ret = dict_set_int64(rsp_dict, key, brick_order);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "Failed to set %s", key);
            goto out;
        }

        snprintf(key, sizeof(key), "vol%" PRId64 ".brick%" PRId64 ".status", i,
                 brick_order);

        ret = glusterd_add_brick_status_to_dict(rsp_dict, volinfo, brickinfo,
                                                key);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
                   "failed to "
                   "add brick status to dict");
            goto out;
        }
        brick_count++;
        brick_order++;
        if (device) {
            GF_FREE(device);
            device = NULL;
        }
    }
    snprintf(key, sizeof(key) - 1, "vol%" PRId64 "_brickcount", volcount);
    ret = dict_set_int64(rsp_dict, key, brick_count);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set %s", key);
        goto out;
    }
    ret = 0;
out:
    if (orig_device)
        GF_FREE(orig_device);

    if (device)
        GF_FREE(device);

    return ret;
}

static int
glusterd_snapshot_pause_tier(xlator_t *this, glusterd_volinfo_t *volinfo)
{
    int ret = -1;
    dict_t *dict = NULL;
    char *op_errstr = NULL;

    GF_VALIDATE_OR_GOTO("glusterd", this, out);
    GF_VALIDATE_OR_GOTO(this->name, volinfo, out);

    if (volinfo->type != GF_CLUSTER_TYPE_TIER) {
        ret = 0;
        goto out;
    }

    dict = dict_new();
    if (!dict) {
        goto out;
    }

    ret = dict_set_int32n(dict, "rebalance-command", SLEN("rebalance-command"),
                          GF_DEFRAG_CMD_PAUSE_TIER);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set rebalance-command");
        goto out;
    }

    ret = dict_set_strn(dict, "volname", SLEN("volname"), volinfo->volname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set volname");
        goto out;
    }

    ret = gd_brick_op_phase(GD_OP_DEFRAG_BRICK_VOLUME, NULL, dict, &op_errstr);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_PAUSE_TIER_FAIL,
               "Failed to pause tier. Errstr=%s", op_errstr);
        goto out;
    }

out:
    if (dict)
        dict_unref(dict);

    return ret;
}

static int
glusterd_snapshot_create_prevalidate(dict_t *dict, char **op_errstr,
                                     dict_t *rsp_dict, uint32_t *op_errno)
{
    char *volname = NULL;
    char *snapname = NULL;
    char key[64] = "";
    int keylen;
    char snap_volname[64] = "";
    char err_str[PATH_MAX] = "";
    int ret = -1;
    int64_t i = 0;
    int64_t volcount = 0;
    glusterd_volinfo_t *volinfo = NULL;
    xlator_t *this = NULL;
    uuid_t *snap_volid = NULL;
    gf_loglevel_t loglevel = GF_LOG_ERROR;
    glusterd_conf_t *conf = NULL;
    int64_t effective_max_limit = 0;
    int flags = 0;
    uint64_t opt_hard_max = GLUSTERD_SNAPS_MAX_HARD_LIMIT;
    char *description = NULL;
    int32_t brick_online = 0;
    int64_t brick_order = 0;

    this = THIS;
    GF_ASSERT(op_errstr);
    conf = this->private;
    GF_ASSERT(conf);
    GF_VALIDATE_OR_GOTO(this->name, op_errno, out);

    ret = dict_get_int64(dict, "volcount", &volcount);
    if (ret) {
        snprintf(err_str, sizeof(err_str),
                 "Failed to "
                 "get the volume count");
        goto out;
    }
    if (volcount <= 0) {
        snprintf(err_str, sizeof(err_str),
                 "Invalid volume count %" PRId64 " supplied", volcount);
        ret = -1;
        goto out;
    }

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        snprintf(err_str, sizeof(err_str), "Failed to get snapname");
        goto out;
    }

    ret = dict_get_strn(dict, "description", SLEN("description"), &description);
    if (description && !(*description)) {
        /* description should have a non-null value */
        ret = -1;
        snprintf(err_str, sizeof(err_str),
                 "Snapshot cannot be "
                 "created with empty description");
        goto out;
    }

    ret = dict_get_int32n(dict, "flags", SLEN("flags"), &flags);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Unable to get flags");
        goto out;
    }

    if (glusterd_find_snap_by_name(snapname)) {
        ret = -1;
        snprintf(err_str, sizeof(err_str),
                 "Snapshot %s already "
                 "exists",
                 snapname);
        *op_errno = EG_SNAPEXST;
        goto out;
    }

    for (i = 1; i <= volcount; i++) {
        keylen = snprintf(key, sizeof(key), "volname%" PRId64, i);
        ret = dict_get_strn(dict, key, keylen, &volname);
        if (ret) {
            snprintf(err_str, sizeof(err_str), "failed to get volume name");
            goto out;
        }
        ret = glusterd_volinfo_find(volname, &volinfo);
        if (ret) {
            snprintf(err_str, sizeof(err_str), "Volume (%s) does not exist ",
                     volname);
            *op_errno = EG_NOVOL;
            goto out;
        }

        ret = -1;
        if (!glusterd_is_volume_started(volinfo)) {
            snprintf(err_str, sizeof(err_str),
                     "volume %s is "
                     "not started",
                     volinfo->volname);
            loglevel = GF_LOG_WARNING;
            *op_errno = EG_VOLSTP;
            goto out;
        }

        if (glusterd_is_defrag_on(volinfo)) {
            snprintf(err_str, sizeof(err_str),
                     "rebalance process is running for the "
                     "volume %s",
                     volname);
            loglevel = GF_LOG_WARNING;
            *op_errno = EG_RBALRUN;
            goto out;
        }

        if (gd_vol_is_geo_rep_active(volinfo)) {
            snprintf(err_str, sizeof(err_str),
                     "geo-replication session is running for "
                     "the volume %s. Session needs to be "
                     "stopped before taking a snapshot.",
                     volname);
            loglevel = GF_LOG_WARNING;
            *op_errno = EG_GEOREPRUN;
            goto out;
        }

        if (volinfo->is_snap_volume == _gf_true) {
            snprintf(err_str, sizeof(err_str), "Volume %s is a snap volume",
                     volname);
            loglevel = GF_LOG_WARNING;
            *op_errno = EG_ISSNAP;
            goto out;
        }

        /* "snap-max-hard-limit" might not be set by user explicitly,
         * in that case it's better to consider the default value.
         * Hence not erroring out if Key is not found.
         */
        ret = dict_get_uint64(
            conf->opts, GLUSTERD_STORE_KEY_SNAP_MAX_HARD_LIMIT, &opt_hard_max);
        if (ret) {
            ret = 0;
            gf_msg_debug(this->name, 0,
                         "%s is not present "
                         "in opts dictionary",
                         GLUSTERD_STORE_KEY_SNAP_MAX_HARD_LIMIT);
        }

        if (volinfo->snap_max_hard_limit < opt_hard_max)
            effective_max_limit = volinfo->snap_max_hard_limit;
        else
            effective_max_limit = opt_hard_max;

        if (volinfo->snap_count >= effective_max_limit) {
            ret = -1;
            snprintf(err_str, sizeof(err_str),
                     "The number of existing snaps has reached "
                     "the effective maximum limit of %" PRIu64
                     ", "
                     "for the volume (%s). Please delete few "
                     "snapshots before taking further snapshots.",
                     effective_max_limit, volname);
            loglevel = GF_LOG_WARNING;
            *op_errno = EG_HRDLMT;
            goto out;
        }

        snprintf(key, sizeof(key), "vol%" PRId64 "_volid", i);
        ret = dict_get_bin(dict, key, (void **)&snap_volid);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
                   "Unable to fetch snap_volid");
            goto out;
        }

        /* snap volume uuid is used as lvm snapshot name.
           This will avoid restrictions on snapshot names
           provided by user */
        GLUSTERD_GET_UUID_NOHYPHEN(snap_volname, *snap_volid);

        ret = glusterd_snap_create_clone_common_prevalidate(
            rsp_dict, flags, snapname, err_str, snap_volname, i, volinfo,
            &loglevel, 0, op_errno);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_PRE_VALIDATION_FAIL,
                   "Failed to pre validate");
            goto out;
        }

        keylen = snprintf(key, sizeof(key),
                          "vol%" PRId64 ".brick%" PRId64 ".status", i,
                          brick_order);
        ret = dict_get_int32n(rsp_dict, key, keylen, &brick_online);
        ret = dict_set_int32(dict, key, brick_online);
        brick_order++;

        ret = glusterd_snapshot_pause_tier(this, volinfo);
        if (ret) {
            gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_SNAP_PAUSE_TIER_FAIL,
                   "Failed to pause tier in snap prevalidate.");
            goto out;
        }
    }

    ret = dict_set_int64(rsp_dict, "volcount", volcount);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set volcount");
        goto out;
    }

    ret = 0;

out:
    if (ret && err_str[0] != '\0') {
        gf_msg(this->name, loglevel, 0, GD_MSG_SNAPSHOT_OP_FAILED, "%s",
               err_str);
        *op_errstr = gf_strdup(err_str);
    }

    gf_msg_trace(this->name, 0, "Returning %d", ret);
    return ret;
}

static int
glusterd_snapshot_remove_prevalidate(dict_t *dict, char **op_errstr,
                                     uint32_t *op_errno, dict_t *rsp_dict)
{
    int32_t ret = -1;
    char *snapname = NULL;
    xlator_t *this = NULL;
    glusterd_snap_t *snap = NULL;

    this = THIS;
    GF_VALIDATE_OR_GOTO("glusterd", this, out);
    GF_VALIDATE_OR_GOTO(this->name, op_errno, out);

    if (!dict || !op_errstr) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_INVALID_ENTRY,
               "input parameters NULL");
        goto out;
    }

    ret = dict_get_strn(dict, "snapname", SLEN("snapname"), &snapname);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_GET_FAILED,
               "Getting the snap name "
               "failed");
        goto out;
    }

    snap = glusterd_find_snap_by_name(snapname);
    if (!snap) {
        gf_msg(this->name, GF_LOG_ERROR, EINVAL, GD_MSG_SNAP_NOT_FOUND,
               "Snapshot (%s) does not exist", snapname);
        *op_errno = EG_NOSNAP;
        ret = -1;
        goto out;
    }

    ret = dict_set_dynstr_with_alloc(dict, "snapuuid",
                                     uuid_utoa(snap->snap_id));
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_DICT_SET_FAILED,
               "Failed to set snap "
               "uuid in response dictionary for %s snapshot",
               snap->snapname);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int
glusterd_zfs_snapshot_prevalidate(dict_t *dict, char **op_errstr, dict_t *rsp_dict,
                              uint32_t *op_errno)
{
    int snap_command = 0;
    xlator_t *this = NULL;
    int ret = -1;

    this = THIS;

    GF_ASSERT(this);
    GF_ASSERT(dict);
    GF_ASSERT(rsp_dict);
    GF_VALIDATE_OR_GOTO(this->name, op_errno, out);

    ret = dict_get_int32n(dict, "type", SLEN("type"), &snap_command);
    if (ret) {
        gf_msg(this->name, GF_LOG_ERROR, 0, GD_MSG_COMMAND_NOT_FOUND,
               "unable to get the type of "
               "the snapshot command");
        goto out;
    }

    switch (snap_command) {
        case (GF_SNAP_OPTION_TYPE_CREATE):
            ret = glusterd_snapshot_create_prevalidate(dict, op_errstr,
                                                       rsp_dict, op_errno);
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_CREATION_FAIL,
                       "Snapshot create "
                       "pre-validation failed");
                goto out;
            }
            break;

        case GF_SNAP_OPTION_TYPE_DELETE:
            ret = glusterd_snapshot_remove_prevalidate(dict, op_errstr,
                                                       op_errno, rsp_dict);
            if (ret) {
                gf_msg(this->name, GF_LOG_WARNING, 0, GD_MSG_SNAP_REMOVE_FAIL,
                       "Snapshot remove "
                       "validation failed");
                goto out;
            }
            break;

        default:
            gf_msg(this->name, GF_LOG_WARNING, EINVAL, GD_MSG_COMMAND_NOT_FOUND,
                   "invalid snap command");
            *op_errno = EINVAL;
            goto out;
    }

    ret = 0;
out:
    return ret;
}

char *snappath_get_brickpath(char *snap_path, char brinkpath[])
{
    int len = 0;
    int len1 = 0;
    int len2 = 0;
    char *str = NULL;

    len1 = strlen(snap_path);
    str = strstr(snap_path, ".zfs");
    printf("%s\n", str);
    len2 = strlen(str);
    len = len1 - len2 - 1;

    strncpy(brinkpath, snap_path, len);
    printf("%s\n", brinkpath);

    return brinkpath;
}
