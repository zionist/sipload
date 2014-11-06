__author__ = 'slaviann'



class TptfHeader(self):
    def __init__(self):
        self.header_format = {
            issuestamp
        }


class Tptf:

    def __init__(self):
        self.header_format = {
            00: "issuestamp",
            4: "compstamp",
            8: "eye",
            12: "version",
            16: "type",
            20: "cc",
            22: "rsn;",
            24: "prio;",
            26: "class",
            28: "transnumb",
            32: "tofunc",
            40: "retfunc",
            48: "flags",
            50: "comptransnumb",
            52: "datalen",
            56: "udata",
            64: "END",
        }


#typedef struct tptf_struct {
#  /* 00 */ guint32 issuestamp;
#  /* 04 */ guint32 compstamp;
#  /* 08 */ char eye[TPTF_HDR_EYE_SIZE];  /* "TPTF" */
#  /* 12 */ char version[TPTF_HDR_VERSION_SIZE];
#  /* 16 */ char type[TPTF_HDR_TYPE_SIZE];
#  /* 20 */ gint16 cc;
#  /* 22 */ gint16 rsn;
#  /* 24 */ guint16 prio;
#  /* 26 */ guint16 class;
#  /* 28 */ guint32 transnumb;
#  /* 32 */ struct ttf tofunc;
#  /* 40 */ struct ttf retfunc;
#  /* 48 */ guint16 flags;
#  /* 50 */ guint16 comptransnumb;
#  /* 52 */ guint32 datalen;
#  /* 56 */ char udata[TPTF_HDR_UDATA_SIZE];
#  /* 64 END */
#} tptf_header_t;
