/*
*********************************************************************************************************
*                                             uC/TELNETs
*                                           Telnet (server)
*
*                    Copyright 2004-2020 Silicon Laboratories Inc. www.silabs.com
*
*                                 SPDX-License-Identifier: APACHE-2.0
*
*               This software is subject to an open source license and is distributed by
*                Silicon Laboratories Inc. pursuant to the terms of the Apache License,
*                    Version 2.0 available at www.apache.org/licenses/LICENSE-2.0.
*
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*
*                                            TELNET SERVER
*
* Filename : telnet-s.c
* Version  : V1.06.00
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*********************************************************************************************************
*                                            INCLUDE FILES
*********************************************************************************************************
*********************************************************************************************************
*/

#define    TELNETs_MODULE
#include  "telnet-s.h"
#include  <Source/net_cfg_net.h>

#ifdef  NET_IPv4_MODULE_EN
#include  <IP/IPv4/net_ipv4.h>
#endif
#ifdef  NET_IPv6_MODULE_EN
#include  <IP/IPv6/net_ipv6.h>
#endif

#include  <Source/net.h>
#include  <Source/net_util.h>
#include  <Source/net_app.h>
#include  <app_cfg.h>


/*
*********************************************************************************************************
*********************************************************************************************************
*                                            LOCAL DEFINES
*********************************************************************************************************
*********************************************************************************************************
*/


#define  TELNETs_BS_CHAR                                  "\b"  /* Backspace  char.                                     */
#define  TELNETs_BS_CHAR_LEN                               2u   /* Baskspace  char len.                                 */

#define  TELNETs_WS_CHAR                                  " "   /* Whitespace char.                                     */
#define  TELNETs_WS_CHAR_LEN                               1u   /* Whitespace char len.                                 */


/*
*********************************************************************************************************
*********************************************************************************************************
*                                       LOCAL GLOBAL VARIABLES
*********************************************************************************************************
*********************************************************************************************************
*/

                                                                /* Used to know if the server is initialized in ...     */
                                                                /* Secure cfg.                                          */
static  const  TELNETs_SECURE_CFG        *TELNETs_SecureCfgPtr = (TELNETs_SECURE_CFG *)DEF_NULL;

static         NET_SOCK_PROTOCOL_FAMILY   TELNETs_ProtocolFamily;


/*
*********************************************************************************************************
*                                           INITIALIZED DATA
*
* Note(s) : (1) This constant table defines the supported telnet options.  Those options should be
*               defined in telnet-s.h, under the "TELNET OPTION DEFINES" section.  Also, the number
*               of options in this table MUST match the TELNET_NBR_OPT_SUPPORTED constant define in
*               the header file.
*********************************************************************************************************
*/

                                                                /* See Note #1.                                         */
static  const  CPU_INT08U  TELNETs_SupportedOptTbl[] = {
    TELNET_OPT_ECHO,
    TELNET_OPT_SUPPRESS_GA
};


/*
*********************************************************************************************************
*********************************************************************************************************
*                                      LOCAL FUNCTION PROTOTYPES
*********************************************************************************************************
*********************************************************************************************************
*/

                                                                            /* ---------------- RX FNCT --------------- */
static  CPU_BOOLEAN   TELNETs_RxSessionData(TELNETs_SESSION         *psession,
                                            CPU_BOOLEAN              echo_en,
                                            TELNETs_ERR             *perr);

static  void          TELNETs_RxOptHandler (TELNETs_SESSION         *psession,
                                            TELNETs_OPT_STATUS_CMD   opt_cmd_rx,
                                            CPU_INT08U               opt_code_rx,
                                            TELNETs_ERR             *perr);

static  CPU_INT32S    TELNETs_Rx           (NET_SOCK_ID              sock_id,
                                            CPU_CHAR                *pdata_buf,
                                            CPU_INT16U               data_buf_len,
                                            TELNETs_ERR             *perr);


                                                                            /* ---------------- TX FNCT --------------- */
static  void          TELNETs_TxOptReq     (TELNETs_SESSION         *psession,
                                            TELNETs_OPT_STATUS_CMD   opt_status,
                                            CPU_INT08U               opt_code,
                                            TELNETs_ERR             *perr);

static  void          TELNETs_TxOptRep     (TELNETs_SESSION         *psession,
                                            TELNETs_OPT_STATUS_CMD   opt_status_req,
                                            CPU_INT08U               opt_code,
                                            TELNETs_OPT             *popt_cur,
                                            TELNETs_ERR             *perr);

static  CPU_BOOLEAN   TELNETs_TxGA         (TELNETs_SESSION         *psesssion,
                                            TELNETs_ERR             *perr);

static  CPU_BOOLEAN   TELNETs_TxCmd        (NET_SOCK_ID              sock_id,
                                            CPU_INT08U               cmd_code,
                                            CPU_INT08U               opt_code,
                                            TELNETs_ERR             *perr);

static  CPU_BOOLEAN   TELNETs_Tx           (NET_SOCK_ID              sock_id,
                                            CPU_CHAR                *pdata_buf,
                                            CPU_INT16U               data_buf_len,
                                            TELNETs_ERR             *perr);


                                                                            /* --------------- NVT FNCTS -------------- */
static  CPU_BOOLEAN   TELNETs_NVTInit      (TELNETs_SESSION         *psession,
                                            TELNETs_ERR             *perr);

static  CPU_BOOLEAN   TELNETs_NVTLogin     (TELNETs_SESSION         *psession,
                                            TELNETs_ERR             *perr);

static  void          TELNETs_NVTPrint     (TELNETs_SESSION         *psession,
                                            CPU_BOOLEAN              echo,
                                            TELNETs_ERR             *perr);

static  void          TELNETs_NVTTxPrompt  (TELNETs_SESSION         *psession,
                                            TELNETs_ERR             *perr);

static  void          TELNETs_NVTGetBuf    (TELNETs_SESSION         *psession,
                                            CPU_CHAR                *dest_buf,
                                            CPU_INT16U               dest_buf_len,
                                            CPU_BOOLEAN              remove_eol,
                                            TELNETs_ERR             *perr);

static  CPU_BOOLEAN   TELNETs_NVTTerminate (TELNETs_SESSION         *psession);


                                                                            /* --------------- CMD FNCT --------------- */
static  CPU_INT16S    TELNETs_Cmd          (CPU_CHAR                *pcmd_line,
                                            TELNETs_SESSION         *psession,
                                            TELNETs_ERR             *perr);

static  CPU_INT16S    TELNETs_CmdHandlerInt(CPU_CHAR                *pcmd_line,
                                            void                    *pcwd,
                                            CPU_BOOLEAN             *psession_active,
                                            void                    *pout_opt,
                                            TELNET_OUT_FNCT          pout_fnct,
                                            TELNETs_ERR             *perr);


                                                                            /* -------------- UTIL FNCTS -------------- */
static  TELNETs_OPT  *TELNETs_GetOpt       (TELNETs_SESSION         *psession,
                                            CPU_INT08U               opt_code);


                                                                            /* ------------ SHELL OUT FNCT ------------ */
static  CPU_INT16S    TELNETs_OutFnct      (CPU_CHAR                *pbuf,
                                            CPU_INT16U               buf_len,
                                            void                    *popt);


/*
*********************************************************************************************************
*                                             TELNETs_Init()
*
* Description : Initialize the TELNET server.
*
* Argument(s) : p_secure_cfg    Desired value for server secure mode :
*
*                                   Secure Configuration Pointer    Server operations will     be secured.
*                                   DEF_NULL                        Server operations will NOT be secured.
*
* Returns     : DEF_OK,   TELNET server initialization successful.
*
*               DEF_FAIL, otherwise.
*
* Note(s)     : (1) TELNETs_Init() MUST be called ...
*
*                   (a) AFTER  product's OS and network have been initialized.
*
*               (2) TELNETs_Init() MUST ONLY be called ONCE from product's application.
*
*               (3) Network security manager MUST be available & enabled to initialize the server in
*                   secure mode.
*********************************************************************************************************
*/

CPU_BOOLEAN  TELNETs_Init (       NET_SOCK_ADDR_FAMILY   family,
                           const  TELNETs_SECURE_CFG    *p_secure_cfg)
{
    CPU_INT16U   nbr_opt;
    CPU_BOOLEAN  rtn_val;
    CPU_SR_ALLOC();


#ifndef  NET_SECURE_MODULE_EN                                   /* See Note #3.                                         */
    if (p_secure_cfg != DEF_NULL) {
        TELNETs_TRACE_DBG(("TELNETs init failed. Security manager NOT available.\n"));
        return (DEF_FAIL);
    }
#endif


    CPU_CRITICAL_ENTER();
    TELNETs_SecureCfgPtr = p_secure_cfg;                        /* Save secure mode cfg.                                */
    switch (family) {
        case NET_SOCK_ADDR_FAMILY_IP_V4:
             TELNETs_ProtocolFamily = NET_SOCK_PROTOCOL_FAMILY_IP_V4;
             break;

        case NET_SOCK_ADDR_FAMILY_IP_V6:
             TELNETs_ProtocolFamily = NET_SOCK_PROTOCOL_FAMILY_IP_V6;
             break;

        default:
             CPU_CRITICAL_EXIT();
             return (DEF_FAIL);
    }
    CPU_CRITICAL_EXIT();

    TELNETs_NbrActiveSessionTask = 0;

    nbr_opt = sizeof(TELNETs_SupportedOptTbl);                  /* Make sure the nbr of opt is consistent.              */
    if (nbr_opt != TELNET_NBR_OPT_SUPPORTED) {
        TELNETs_TRACE_DBG(("Telnet server initialization failed : inconsistent number of options\n\r"));
        return (DEF_FAIL);
    }


    TELNETs_TRACE_INFO(("Telnet server initialization\n\r"));
    rtn_val = TELNETs_OS_ServerTaskInit((void *)&family);
    if (rtn_val == DEF_FAIL) {
        TELNETs_TRACE_DBG(("Telnet server initialization failed\n\r"));
    }

    return (rtn_val);
}


/*
*********************************************************************************************************
*                                           TELNETs_ServerTask()
*
* Description : (1) Main TELNET server code :
*
*                   (a) Prepare socket and listen for clients
*                   (b) Accept incoming connections
*                   (c) Process connection
*
*
* Argument(s) : p_arg           Argument passed to the task.
*
* Return(s)   : none.
*
* Note(s)     : (2) On fatal error, close the server socket, break accept loop and re-open listen
*                   (server) socket.
*
*               (3) If all available sessions are in use, reply to the client that the service is not
*                   currently available and close the session socket.
*********************************************************************************************************
*/

void  TELNETs_ServerTask (void  *p_arg)
{
#ifdef  NET_IPv4_MODULE_EN
    NET_IPv4_ADDR              ipv4_addr;
#endif
    CPU_INT08U                *p_addr;
    NET_IP_ADDR_LEN            addr_len;
    NET_PORT_NBR               port_nbr;
    NET_SOCK_ID                sock_id_listen;
    NET_SOCK_ID                sock_id_session;
    NET_SOCK_ADDR              addr_server;
    NET_SOCK_ADDR_LEN          addr_server_size;
    NET_SOCK_ADDR              addr_client;
    NET_SOCK_ADDR_LEN          addr_client_size;
    CPU_INT16U                 msg_len;
    CPU_BOOLEAN                rtn_val;
    TELNETs_ERR                err_telnet;
    NET_ERR                    net_err;



   (void)p_arg;

    while (DEF_ON) {
                                                                /* -------- PREPARE SOCKET & LISTEN FOR CLIENTS ------- */
                                                                /* Open a sock.                                         */
        sock_id_listen = NetSock_Open(TELNETs_ProtocolFamily,
                                      NET_SOCK_TYPE_STREAM,
                                      NET_SOCK_PROTOCOL_TCP,
                                     &net_err);
        if (net_err != NET_SOCK_ERR_NONE) {
            TELNETs_OS_TaskSuspend();
        }

#ifdef  NET_SECURE_MODULE_EN                               /* Set or clear socket secure mode.                     */
        if (TELNETs_SecureCfgPtr != DEF_NULL) {
            (void)NetSock_CfgSecure(sock_id_listen,
                                    DEF_YES,
                                   &net_err);

            if (net_err != NET_SOCK_ERR_NONE) {
                TELNETs_TRACE_INFO(("TELNETs NetSock_Open() failed: No secure socket available.\n"));
                NetSock_Close(sock_id_listen, &net_err);
                TELNETs_OS_TaskSuspend();
            }

            (void)NetSock_CfgSecureServerCertKeyInstall(sock_id_listen,
                                                        TELNETs_SecureCfgPtr->CertPtr,
                                                        TELNETs_SecureCfgPtr->CertLen,
                                                        TELNETs_SecureCfgPtr->KeyPtr,
                                                        TELNETs_SecureCfgPtr->KeyLen,
                                                        TELNETs_SecureCfgPtr->Fmt,
                                                        TELNETs_SecureCfgPtr->CertChain,
                                                       &net_err);

            if (net_err != NET_SOCK_ERR_NONE) {
                TELNETs_TRACE_INFO(("TELNETs NetSock_Open() failed: No secure socket available.\n"));
                NetSock_Close(sock_id_listen, &net_err);
                TELNETs_OS_TaskSuspend();
            }
        }
#endif
                                                                /* Set Sock Cfg to Block mode.                          */
        NetSock_CfgBlock( sock_id_listen,
                          DEF_YES,
                         &net_err);
        if (net_err != NET_SOCK_ERR_NONE) {
            TELNETs_OS_TaskSuspend();
        }

        Mem_Set(&addr_server, (CPU_CHAR)0, NET_SOCK_ADDR_SIZE); /* Bind a local address so the client can send to us.   */

        switch (TELNETs_ProtocolFamily) {
#ifdef  NET_IPv4_MODULE_EN
            case NET_SOCK_PROTOCOL_FAMILY_IP_V4:
                 ipv4_addr = NET_UTIL_HOST_TO_NET_32(NET_IPv4_ADDR_ANY);
                 p_addr    = (CPU_INT08U *)&ipv4_addr;
                 addr_len  = NET_IPv4_ADDR_SIZE;
                 break;
#endif
#ifdef  NET_IPv6_MODULE_EN
            case NET_SOCK_PROTOCOL_FAMILY_IP_V6:
                 p_addr    = (CPU_INT08U *)&NET_IPv6_ADDR_ANY;
                 addr_len  = NET_IPv6_ADDR_SIZE;
                 break;
#endif

            default:
                 p_addr    = (CPU_INT08U *)0;
                 TELNETs_OS_TaskSuspend();
        }

        if (TELNETs_SecureCfgPtr != DEF_NULL) {                 /* Set the port according to the secure mode cfg.       */
            port_nbr = TELNETs_CFG_PORT_SERVER_SECURE;
        } else {
            port_nbr = TELNETs_CFG_PORT_SERVER;
        }

        NetApp_SetSockAddr(&addr_server,
                            TELNETs_ProtocolFamily,
                            port_nbr,
                            p_addr,
                            addr_len,
                           &net_err);

        addr_server_size = NET_SOCK_ADDR_SIZE;
                                                                /* Bind to local addr and TELNETs port.                 */
        NetSock_Bind((NET_SOCK_ID      ) sock_id_listen,
                     (NET_SOCK_ADDR   *)&addr_server,
                     (NET_SOCK_ADDR_LEN) addr_server_size,
                     (NET_ERR         *)&net_err);
        if (net_err != NET_SOCK_ERR_NONE) {
            NetSock_Close(sock_id_listen, &net_err);
            TELNETs_OS_TaskSuspend();
        }

                                                                /* Listen for clients.                                  */
        NetSock_Listen( sock_id_listen,
                        TELNETs_CONN_Q_SIZE,
                       &net_err);
        if (net_err != NET_SOCK_ERR_NONE) {
            NetSock_Close(sock_id_listen, &net_err);
            TELNETs_OS_TaskSuspend();
        }

        while (DEF_ON) {
            CPU_BOOLEAN  flag = DEF_DISABLED;

                                                                /* ---------------- ACCEPT INCOMING CONN -------------- */
            addr_client_size = sizeof(addr_client);

                                                                /* Accept conn.                                         */
            sock_id_session = NetSock_Accept( sock_id_listen,
                                             &addr_client,
                                             &addr_client_size,
                                             &net_err);
            switch (net_err) {
                case NET_SOCK_ERR_NONE:
                     NetSock_OptSet(sock_id_session,
                                    NET_SOCK_PROTOCOL_TCP,
                                    NET_SOCK_OPT_TCP_NO_DELAY,
                                   &flag,
                                    sizeof(flag),
                                   &net_err);
                     break;

                case NET_INIT_ERR_NOT_COMPLETED:
                case NET_ERR_FAULT_NULL_PTR:
                case NET_SOCK_ERR_NONE_AVAIL:
                case NET_SOCK_ERR_CONN_ACCEPT_Q_NONE_AVAIL:
                case NET_SOCK_ERR_CONN_SIGNAL_TIMEOUT:
                case NET_ERR_FAULT_LOCK_ACQUIRE:
                     continue;                                  /* Ignore transitory sock err.                          */

                case NET_SOCK_ERR_NOT_USED:
                case NET_SOCK_ERR_INVALID_SOCK:
                case NET_SOCK_ERR_INVALID_TYPE:
                case NET_SOCK_ERR_INVALID_FAMILY:
                case NET_SOCK_ERR_INVALID_STATE:
                case NET_SOCK_ERR_INVALID_OP:
                case NET_SOCK_ERR_CONN_FAIL:
                default:
                     break;
            }

            if (net_err != NET_SOCK_ERR_NONE) {                 /* See Note #2.                                         */
                NetSock_Close(sock_id_listen, &net_err);
                break;
            }

                                                                /* -------------------- PROCESS CONN ------------------ */
                                                                /* See Note #3.                                         */
            if (TELNETs_NbrActiveSessionTask >= TELNETs_SESSION_TASKS_MAX) {
                msg_len = Str_Len((CPU_CHAR *)TELNETs_NO_SERVICE_STR);
                TELNETs_Tx((NET_SOCK_ID) sock_id_session,
                           (CPU_CHAR  *) TELNETs_NO_SERVICE_STR,
                           (CPU_INT16U ) msg_len,
                           (TELNETs_ERR *)&err_telnet);

                NetSock_Close(sock_id_session, &net_err);
                continue;
            }

            TELNETs_NbrActiveSessionTask++;
            TELNETs_ActiveSession.sock_id = sock_id_session;
            rtn_val = TELNETs_OS_SessionTaskInit((void *)&TELNETs_ActiveSession);
            if (rtn_val == DEF_FAIL) {
                msg_len = Str_Len((CPU_CHAR *)TELNETs_NO_SERVICE_STR);
                TELNETs_Tx((NET_SOCK_ID) sock_id_session,
                           (CPU_CHAR  *) TELNETs_NO_SERVICE_STR,
                           (CPU_INT16U ) msg_len,
                           (TELNETs_ERR *)&err_telnet);

                NetSock_Close(sock_id_session, &net_err);
            }
        }

        if (net_err != NET_SOCK_ERR_NONE) {
            continue;                                           /* Re-open sock on accept err.                          */
        }
    }
}


/*
*********************************************************************************************************
*                                         TELNETs_SessionTask()
*
* Description : (1) Main TELNET session code :
*
*                   (a) Initialize NVT
*                   (b) Receive data from client
*                   (c) Process received data
*                   (d) Terminate session when needed
*
*
* Argument(s) : p_arg           Argument passed to the task.
*
* Return(s)   : none.
*
* Note(s)     : (1) If TELNETs_CmdProcess() returns TELNETs_ERR_CMD_EXEC, meaning there was an error
*                   while executing command, NO error message is transmitted by the session task.  It is
*                   the command responsibility to output such error to the client.
*********************************************************************************************************
*/

void  TELNETs_SessionTask (void  *p_arg)
{
    TELNETs_SESSION  *psession;
    CPU_BOOLEAN       init_done;
    CPU_INT16U        tx_str_len;
    TELNETs_ERR       err_telnet;
    TELNETs_ERR       err_cmd;
    NET_ERR           err_net;
#if (TELNETs_CFG_FS_EN == DEF_ENABLED)
    CPU_CHAR          working_dir[TELNETs_CFG_FS_MAX_PATH_NAME_LEN];
#endif


    psession                 = p_arg;
    psession->session_active = DEF_NO;

                                                                /* ---------------------- INIT NVT -------------------- */
    init_done = TELNETs_NVTInit(psession, &err_telnet);
    if (init_done == DEF_OK) {
        psession->session_active = DEF_YES;

#if (TELNETs_CFG_FS_EN == DEF_ENABLED)
        Str_Copy(working_dir, (CPU_CHAR *)"\\");
        psession->pcur_working_dir = (void *)working_dir;
#else
        psession->pcur_working_dir = (void *)0;
#endif
    }


    while (psession->session_active == DEF_YES) {
                                                                /* ---------------- RX DATA FROM CLIENT --------------- */
        TELNETs_RxSessionData(psession, DEF_YES, &err_telnet);

                                                                /* ----------------- PROCESS RX'D DATA ---------------- */
        switch (err_telnet) {
            case TELNETs_ERR_NONE:
            TELNETs_NVTPrint(psession, DEF_YES, &err_telnet);

                 if (err_telnet == TELNETs_ERR_NONE_EOL_RX) {   /* If EOL received ...                                  */
                                                                /* ... parse and invoke user fnct.                      */
                     if (psession->nvt_buf_len > TELNETs_EOL_STR_LEN) {
                                                                /* Rem EOL.                                             */
                         psession->nvt_buf[psession->nvt_buf_len - 2] = (CPU_CHAR)0;
                         psession->nvt_buf_len = psession->nvt_buf_len - 2;

                         TELNETs_Cmd( psession->nvt_buf,
                                      psession,
                                     &err_cmd);

                         switch (err_cmd) {
                             case TELNETs_ERR_NONE:             /* No err ...                                           */
                                  break;                        /* ... nothing to do.                                   */

                             case TELNETs_ERR_CMD_PROCESS:      /* Err processing cmd ...                               */
                                                                /* ... tx err msg.                                      */
                                  tx_str_len = Str_Len((CPU_CHAR *)TELNETs_CMD_PROCESS_ERR_STR);
                                  TELNETs_Tx((NET_SOCK_ID  ) psession->sock_id,
                                             (CPU_CHAR    *) TELNETs_CMD_PROCESS_ERR_STR,
                                             (CPU_INT16U   ) tx_str_len,
                                             (TELNETs_ERR *)&err_telnet);
                                  break;

                             case TELNETs_ERR_CMD_EXEC:         /* Err executing cmd ...                                */
                                  break;                        /* ... nothing to do (see Note #1).                     */

                             default:
                                  break;
                         }
                     }

                     psession->nvt_buf_len = 0;
                                                                /* Tx cmd prompt and GA.                                */
                     if (psession->session_active == DEF_YES) {
                        TELNETs_NVTTxPrompt(psession, &err_telnet);
                        TELNETs_TxGA(psession, &err_telnet);
                     }
                 }
                 break;

            case TELNETs_ERR_RX_TIMEOUT:
            case TELNETs_ERR_CONN_CLOSED:
            case TELNETs_ERR_RX:

            default:
                 psession->session_active = DEF_NO;
                 break;
        }
    }

                                                                /* ----------------- TERMINATE SESSION ---------------- */
    TELNETs_TRACE_INFO(("Telnet server closing session socket.\n\r"));
    NetSock_Close(psession->sock_id, &err_net);

    TELNETs_NVTTerminate(psession);

    TELNETs_TRACE_INFO(("Telnet server deleting session task.\n\r"));
    TELNETs_NbrActiveSessionTask--;
    TELNETs_OS_TaskDelete();
}


/*
*********************************************************************************************************
*********************************************************************************************************
*                                           LOCAL FUNCTIONS
*********************************************************************************************************
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*                                          TELNETs_RxSessionData()
*
* Description : Receive data from telnet session.
*
* Argument(s) : psession        Pointer to session structure.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE            No error.
*
*                                                                       ----- RETURNED BY TELNETs_Rx() : -----
*                               TELNETs_ERR_NONE            No error.
*                               TELNETs_ERR_SOCK            Socket error.
*                               TELNETs_ERR_CONN_CLOSED     Connection to client closed.
*                               TELNETs_ERR_RX_TIMEOUT      No data received before inactivity timeout
*                                                           expired.
*                               TELNETs_ERR_RX              Other receive error.
*
* Return(s)   : DEF_OK          Reception successful.
*               DEF_FAIL        Reception failed.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  CPU_BOOLEAN  TELNETs_RxSessionData (TELNETs_SESSION  *psession,
                                            CPU_BOOLEAN       echo_en,
                                            TELNETs_ERR      *perr)
{
#if  (TELNETs_CFG_ECHO_EN == DEF_ENABLED)
    TELNETs_ERR  err;
#endif
    CPU_INT32S   rx_data_len;


                                                                /* ---------------------- RX DATA --------------------- */
    rx_data_len = TELNETs_Rx(psession->sock_id,
                             psession->rx_buf + psession->rx_buf_len,
                             TELNETs_CFG_RX_BUF_LEN - psession->rx_buf_len,
                             perr);

    if (*perr != TELNETs_ERR_NONE) {
        return (DEF_FAIL);
    }

#if  (TELNETs_CFG_ECHO_EN == DEF_ENABLED)
    if (echo_en == DEF_YES) {
        TELNETs_Tx(psession->sock_id, psession->rx_buf + psession->rx_buf_len, rx_data_len, &err);
    }
#else
    (void)echo_en;
#endif

    psession->rx_buf_len += rx_data_len;                        /* Inc rx buf len.                                      */

    return (DEF_OK);
}


/*
*********************************************************************************************************
*                                            TELNETs_RxOptHandler()
*
* Description : Receive option request or reply :
*
*               (a) Get current option status, if any
*               (b) If option supported, determine if it is a reply
*               (c) Process option
*
*
* Argument(s) : psession        Pointer to session structure.
*               opt_cmd_rx      Option status command received.
*               opt_code_rx     Option code           received.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE                           No error.
*                               TELNETs_ERR_OPT_STATUS_UNKNOWN             Unknown option status.
*
*                                                                       -------- RETURNED BY TELNETs_TxCmd(): --------
*                               TELNETs_ERR_TX                             Error transmitting.
*
*                                                                       ------ RETURNED BY TELNETs_TxOptRep() : ------
*                               TELNETs_ERR_NONE_OPT_STATUS_NOT_CHANGED    Request not asking for status change.
*                               TELNETs_ERR_OPT_STATUS_UNKNOWN             Unknown option status.
*                               TELNETs_ERR_TX                             Error transmitting.
*
* Return(s)   : none.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  void  TELNETs_RxOptHandler (TELNETs_SESSION         *psession,
                                    TELNETs_OPT_STATUS_CMD   opt_cmd_rx,
                                    CPU_INT08U               opt_code_rx,
                                    TELNETs_ERR             *perr)
{
    TELNETs_OPT             *popt_cur;
    TELNETs_OPT_STATUS_CMD   int_opt_status;
    CPU_BOOLEAN              is_opt_rep;
    TELNETs_OPT_STATUS_CMD  *pstatus;
    CPU_BOOLEAN             *pstatus_req_tx;


   *perr       = TELNETs_ERR_NONE;
    is_opt_rep = DEF_NO;


                                                                /* ---------------- GET CUR OPT STATUS ---------------- */
    popt_cur = TELNETs_GetOpt(psession, opt_code_rx);


                                                                /* ------------- DETERMINE IF OPT IS A REP ------------ */
    if (popt_cur != (TELNETs_OPT *)0) {
        switch (opt_cmd_rx) {
            case TELNETs_OPT_STATUS_CMD_WILL:                               /* Client-side (peer host) opt.                         */
            case TELNETs_OPT_STATUS_CMD_WONT:
                 if (popt_cur->client_status_req_tx == DEF_YES) {
                     is_opt_rep     =  DEF_YES;
                     pstatus        = &popt_cur->client_status;
                     pstatus_req_tx = &popt_cur->client_status_req_tx;

                     int_opt_status = opt_cmd_rx == TELNETs_OPT_STATUS_CMD_WILL ? TELNETs_OPT_STATUS_CMD_DO :
                                                                                  TELNETs_OPT_STATUS_CMD_DONT;
                 }
                 break;

            case TELNETs_OPT_STATUS_CMD_DO:                                 /* Server-side (this host) opt.                         */
            case TELNETs_OPT_STATUS_CMD_DONT:
                 if (popt_cur->server_status_req_tx == DEF_YES) {
                     is_opt_rep     =  DEF_YES;
                     pstatus        = &popt_cur->server_status;
                     pstatus_req_tx = &popt_cur->server_status_req_tx;

                     int_opt_status = opt_cmd_rx == TELNETs_OPT_STATUS_CMD_DO ? TELNETs_OPT_STATUS_CMD_WILL :
                                                                                TELNETs_OPT_STATUS_CMD_WONT;
                 }
                 break;

            default:
                *perr = TELNETs_ERR_OPT_STATUS_UNKNOWN;
                 break;
            }
    }

    if (*perr != TELNETs_ERR_NONE) {                            /* Rtn if opt status unknown.                           */
        return;
    }


                                                                /* -------------------- PROCESS OPT ------------------- */
    if (is_opt_rep == DEF_YES) {                                /* If opt is a rep ...                                  */
        if (*pstatus == int_opt_status) {                       /* If current status identical to rx'd one ...          */
            TELNETs_TxCmd(psession->sock_id,                    /* ... req refused, tx ack.                             */
                          int_opt_status,
                          opt_code_rx,
                          perr);
        } else {                                                /* Else ...                                             */
           *pstatus = int_opt_status;                           /* ... req accepted.                                    */
        }

       *pstatus_req_tx = DEF_NO;                                /* Req serviced, unset flag.                            */

    } else {                                                    /* Else ...                                             */
        TELNETs_TxOptRep(psession,                              /* ... opt is a req, tx rep.                            */
                         opt_cmd_rx,
                         opt_code_rx,
                         popt_cur,
                         perr);
    }
}


/*
*********************************************************************************************************
*                                               TELNETs_Rx()
*
* Description : (1) Receive data from socket :
*
*                   (a) Configure receive timeout value
*                   (b) Receive data
*
*
* Argument(s) : sock_id         Session socket id.
*               pdata_buf       Pointer to data buffer that will receive client data.
*               data_buf_len    Size of the data buffer (in octets).
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE            No error.
*                               TELNETs_ERR_SOCK            Socket error.
*                               TELNETs_ERR_CONN_CLOSED     Connection to client closed.
*                               TELNETs_ERR_RX_TIMEOUT      No data received before inactivity timeout
*                                                           expired.
*                               TELNETs_ERR_RX              Other receive error.
*
* Return(s)   : Number of positive data octets received, if NO errors.
*
*               NET_SOCK_BSD_RTN_CODE_CONN_CLOSED (0),   if socket connection closed.
*
*               NET_SOCK_BSD_ERR_RX (-1),                otherwise.
*
* Note(s)     : (2) The receive timeout value is configured using the TELNETs_CFG_INACTIVITY_TIMEOUT_S
*                   configuration variable.
*
*               (3) At this point, the function will return when either:
*
*                   (a) data is received from the client
*                   (b) the connection is closed.
*                   (c) the receive timeout expired
*********************************************************************************************************
*/

static  CPU_INT32S  TELNETs_Rx (NET_SOCK_ID   sock_id,
                                CPU_CHAR     *pdata_buf,
                                CPU_INT16U    data_buf_len,
                                TELNETs_ERR  *perr)
{
    CPU_INT32S  rx_data_len;
    NET_ERR     err;


                                                                /* ------------------ SET RX TIMEOUT ------------------ */
                                                                /* See Note #2.                                         */
    NetSock_CfgTimeoutRxQ_Set((NET_SOCK_ID) sock_id,
                              (CPU_INT32U ) TELNETs_CFG_INACTIVITY_TIMEOUT_S * DEF_TIME_NBR_mS_PER_SEC,
                              (NET_ERR   *)&err);

    if (err != NET_SOCK_ERR_NONE) {
       *perr = TELNETs_ERR_SOCK;
        return (NET_SOCK_BSD_ERR_RX);
    }


                                                                /* ---------------------- RX DATA --------------------- */
                                                                /* See Note #3.                                         */
    rx_data_len = NetSock_RxData((NET_SOCK_ID) sock_id,
                                 (void      *) pdata_buf,
                                 (CPU_INT16S ) data_buf_len,
                                 (CPU_INT16S ) NET_SOCK_FLAG_NONE,
                                 (NET_ERR   *)&err);

    if (rx_data_len > 0) {                                      /* Data rx'd.                                           */
       *perr = TELNETs_ERR_NONE;

    } else if (rx_data_len == NET_SOCK_BSD_RTN_CODE_CONN_CLOSED) {
       *perr = TELNETs_ERR_CONN_CLOSED;                         /* Conn has been closed.                                */

    } else {                                                    /* Nothing rx'd ...                                     */
        if (err == NET_SOCK_ERR_RX_Q_EMPTY) {                   /* ... and rx Q empty.                                  */
           *perr = TELNETs_ERR_RX_TIMEOUT;
        } else {                                                /* ... and other rx error.                              */
           *perr = TELNETs_ERR_RX;
        }
    }

    return (rx_data_len);
}


/*
*********************************************************************************************************
*                                          TELNETs_TxOptReq()
*
* Description : (1) Transmit option request.
*
*                   (a) Get current option status structure
*                   (b) Get current option status
*                   (c) Validate request
*                   (d) Transmit request
*
*
* Argument(s) : psession        Pointer to session structure.
*               opt_status      Option status command for the request.
*               opt_code        Option code           for the request.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE                         No error.
*                               TELNETs_ERR_NONE_OPT_STATUS_NOT_CHANGED  Request not asking for status change.
*                               TELNETs_ERR_OPT_NOT_SUPPORTED            Unsupported option.
*                               TELNETs_ERR_OPT_STATUS_UNKNOWN           Unknown     option status.
*
*                                                                       ----- RETURNED BY TELNETs_Tx() : -----
*                               TELNETs_ERR_TX                           Error transmitting.
*
* Return(s)   : none.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  void  TELNETs_TxOptReq (TELNETs_SESSION         *psession,
                                TELNETs_OPT_STATUS_CMD   opt_status,
                                CPU_INT08U               opt_code,
                                TELNETs_ERR             *perr)
{
    TELNETs_OPT             *popt_cur;
    TELNETs_OPT_STATUS_CMD  *pstatus;
    CPU_BOOLEAN             *preq_tx;


   *perr = TELNETs_ERR_NONE;

                                                                /* ------------ GET CUR OPT STATUS STRUCT ------------- */
    popt_cur = TELNETs_GetOpt(psession, opt_code);

    if (popt_cur == (TELNETs_OPT *)0) {                         /* Rtn if opt not supported.                            */
       *perr = TELNETs_ERR_OPT_NOT_SUPPORTED;
        return;
    }


                                                                /* ---------------- GET CUR OPT STATUS ---------------- */
    switch (opt_status) {
            case TELNETs_OPT_STATUS_CMD_DO:                     /* Client-side (peer host) opt.                         */
            case TELNETs_OPT_STATUS_CMD_DONT:
                 pstatus = &popt_cur->client_status;
                 preq_tx = &popt_cur->client_status_req_tx;
                 break;

            case TELNETs_OPT_STATUS_CMD_WILL:                   /* Server-side (this host) opt.                         */
            case TELNETs_OPT_STATUS_CMD_WONT:
                 pstatus = &popt_cur->server_status;
                 preq_tx = &popt_cur->server_status_req_tx;
                 break;

            default:
                *perr = TELNETs_ERR_OPT_STATUS_UNKNOWN;
                 break;
    }

    if (*perr != TELNETs_ERR_NONE) {                            /* Rtn if opt status unknown.                           */
        return;
    }


                                                                /* ------------------- VALIDATE REQ ------------------- */
    if (opt_status == *pstatus) {                               /* If req'd opt status already set ...                  */
       *perr = TELNETs_ERR_NONE_OPT_STATUS_NOT_CHANGED;         /* ... no not tx req and rtn.                           */
        return;
    }


                                                                /* ---------------------- TX REQ ---------------------- */
    TELNETs_TxCmd(psession->sock_id,
                  opt_status,
                  opt_code,
                  perr);

    if (*perr == TELNETs_ERR_NONE) {
       *preq_tx = DEF_YES;                                      /* Set req_tx flag so reply are identified.             */
    }
}


/*
*********************************************************************************************************
*                                             TELNETs_TxOptRep()
*
* Description : (1) Transmit option reply and set current option accordingly :
*
*                   (a) Validate    option request and set reply
*                   (b) Transmit    option reply
*                   (c) Set current option status
*
*
* Argument(s) : psession        Pointer to session structure.
*               opt_status_req  Option reply status command.
*               opt_code        Option reply code.
*               popt_cur        Pointer to current option status.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE                           No error.
*                               TELNETs_ERR_NONE_OPT_STATUS_NOT_CHANGED    Request not asking for status change.
*                               TELNETs_ERR_OPT_STATUS_UNKNOWN             Unknown option status.
*
*                                                                       -------- RETURNED BY TELNETs_TxCmd(): --------
*                               TELNETs_ERR_TX                             Error transmitting.
*
* Return(s)   : none.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  void  TELNETs_TxOptRep (TELNETs_SESSION         *psession,
                                TELNETs_OPT_STATUS_CMD   opt_status_req,
                                CPU_INT08U               opt_code,
                                TELNETs_OPT             *popt_cur,
                                TELNETs_ERR             *perr)
{
    TELNETs_OPT_STATUS_CMD   opt_status;
    TELNETs_OPT_STATUS_CMD  *popt_status;
    CPU_INT08U               opt_code_rep;
    CPU_INT08U               opt_status_rep;


    opt_code_rep = opt_code;
    opt_status   = TELNETs_OPT_STATUS_CMD_DONT;
    popt_status  = (void *)0;
   *perr         = TELNETs_ERR_NONE;

                                                                /* ------------- VALIDATE OPT REQ & SET REP ----------- */
    if (popt_cur != (TELNETs_OPT *)0) {                         /* If popt_cur not NULL ...                             */
        switch (opt_status_req) {                               /* ... opt is supported, treat it.                      */
            case TELNETs_OPT_STATUS_CMD_WILL:                   /* Client-side (peer host) opt.                         */
            case TELNETs_OPT_STATUS_CMD_WONT:
                 opt_status = opt_status_req == TELNETs_OPT_STATUS_CMD_WILL ? TELNETs_OPT_STATUS_CMD_DO:
                                                                              TELNETs_OPT_STATUS_CMD_DONT;
                 if (opt_status != popt_cur->client_status) {
                     popt_status    = &popt_cur->client_status;
                     opt_status_rep =  opt_status;
                 } else {
                    *perr = TELNETs_ERR_NONE_OPT_STATUS_NOT_CHANGED;
                 }
                 break;

            case TELNETs_OPT_STATUS_CMD_DO:                     /* Server-side (this host) opt.                         */
            case TELNETs_OPT_STATUS_CMD_DONT:
                 opt_status = opt_status_req == TELNETs_OPT_STATUS_CMD_DO ? TELNETs_OPT_STATUS_CMD_WILL :
                                                                            TELNETs_OPT_STATUS_CMD_WONT;
                 if (opt_status != popt_cur->server_status) {
                     popt_status    = &popt_cur->server_status;
                     opt_status_rep =  opt_status;
                 } else {
                    *perr = TELNETs_ERR_NONE_OPT_STATUS_NOT_CHANGED;
                 }
                 break;

            default:
                *perr = TELNETs_ERR_OPT_STATUS_UNKNOWN;
                 break;
        }

    } else {                                                    /* Else ...                                             */
        switch (opt_status_req) {                               /* ... opt is NOT supported, refuse it.                 */
            case TELNETs_OPT_STATUS_CMD_WILL:
                 opt_status_rep = TELNETs_OPT_STATUS_CMD_DONT;
                 break;

            case TELNETs_OPT_STATUS_CMD_DO:
                 opt_status_rep = TELNETs_OPT_STATUS_CMD_WONT;
                 break;

            default:
                *perr = TELNETs_ERR_OPT_STATUS_UNKNOWN;
                 break;
        }
    }


    if (*perr != TELNETs_ERR_NONE) {
        return;
    }

                                                                /* -------------------- TX OPT REP -------------------- */
    TELNETs_TxCmd(psession->sock_id,
                  opt_status_rep,
                  opt_code_rep,
                  perr);

                                                                /* ---------------- SET CUR OPT STATUS ---------------- */
    if (*perr == TELNETs_ERR_NONE) {
        if (popt_status != (void *)0) {                         /* If  ptr not NULL ...                                 */
           *popt_status = opt_status;                           /* ... set the ptr value.                               */
        }
    }
}


/*
*********************************************************************************************************
*                                             TELNETs_TxGA()
*
* Description : Transmit Go Ahead, if SUPPRESS_GA not enabled.
*
* Argument(s) : psession        Pointer to session structure.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE            No error.
*
*                                                                       --------- RETURNED BY TELNETs_TxCmd() : ---------
*                               TELNETs_ERR_TX              Error transmitting.
*
* Return(s)   : DEF_YES, Go Ahead transmitted (or attempted).
*               DEF_NO,  otherwise.
*
* Note(s)     : (1) Returning 'DEF_YES' does not guarantee that a Go Ahead has been transmitted.  Check
*                   the variable receiving the return error code to make sure the transmission was
*                   completed.
*********************************************************************************************************
*/

static  CPU_BOOLEAN   TELNETs_TxGA (TELNETs_SESSION  *psession,
                                    TELNETs_ERR      *perr)
{
    TELNETs_OPT      *popt;


    popt = TELNETs_GetOpt(psession, TELNET_OPT_SUPPRESS_GA);

    if (popt != (TELNETs_OPT *)0) {
        if (popt->server_status == TELNETs_OPT_STATUS_CMD_WILL) {
           *perr = TELNETs_ERR_NONE;
            return (DEF_NO);
        }
    }


    TELNETs_TxCmd(psession->sock_id,
                  TELNETs_OPT_STATUS_CMD_GA,
                  TELNET_NO_OPT,
                  perr);

    return (DEF_YES);                                           /* See Note #1.                                         */
}


/*
*********************************************************************************************************
*                                              TELNETs_TxCmd()
*
* Description : Transmit command
*
* Argument(s) : sock_id         Session socket id.
*               cmd_code        Command         code.
*               opt_code        Optional option code.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                                                                       --------- RETURNED BY TELNETs_Tx() : ---------
*                               TELNETs_ERR_NONE            No error.
*                               TELNETs_ERR_TX              Error transmitting.
*
* Return(s)   : DEF_OK          Transmission successful.
*               DEF_FAIL        Transmission failed.
*
* Note(s)     : (1) If a stand-alone command is to be sent (by opposition to an option command), the
*                   opt_code parameter SHOULD be passed TELNET_NO_OPT.  Indeed, when the cmd_code is not
*                   one of these:
*
*                       (a) TELNET_CMD_WILL
*                       (b) TELNET_CMD_WONT
*                       (c) TELNET_CMD_DO
*                       (d) TELNET_CMD_DONT
*
*                   the opt_code parameter is not taken into account.
*
*               (2) No command validation is performed by this function.  It is the caller's
*                   responsibility to make sure the specified command transmitted is valid and is
*                   supported.
*********************************************************************************************************
*/

static  CPU_BOOLEAN  TELNETs_TxCmd (NET_SOCK_ID   sock_id,
                                    CPU_INT08U    cmd_code,
                                    CPU_INT08U    opt_code,
                                    TELNETs_ERR  *perr)
{
    CPU_CHAR     opt_tx_buf[TELNETs_CMD_MAX_BUF_LEN];
    CPU_INT16U   len;

                                                                /* Set IAC and cmd code.                                */
    opt_tx_buf[TELNETs_CMD_IAC_OFFSET] = TELNETs_OPT_STATUS_CMD_IAC;
    opt_tx_buf[TELNETs_CMD_CMD_OFFSET] = cmd_code;


    switch(cmd_code) {
        case TELNETs_OPT_STATUS_CMD_WILL:
        case TELNETs_OPT_STATUS_CMD_WONT:
        case TELNETs_OPT_STATUS_CMD_DO:
        case TELNETs_OPT_STATUS_CMD_DONT:
             opt_tx_buf[TELNETs_CMD_OPT_OFFSET] = opt_code;     /* Set opt code.                                        */
             len = TELNETs_CMD_BUF_LEN_WITH_OPT;
             break;

        default:
             len = TELNETs_CMD_BUF_LEN_NO_OPT;                  /* No opt code.                                         */
             break;
    }


    TELNETs_Tx(sock_id,
               opt_tx_buf,
               len,
               perr);
    if (*perr != TELNETs_ERR_NONE) {
        return (DEF_FAIL);
    }

    return (DEF_OK);
}


/*
*********************************************************************************************************
*                                             TELNETs_Tx()
*
* Description : Transmit data to socket, handling transient errors and incomplete buffer transmit.
*
* Argument(s) : sock_id         Session socket id.
*               pdata_buf       Pointer to data buffer to send.
*               data_buf_len    Length of  data buffer to send.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE            No error.
*                               TELNETs_ERR_TX              Error transmitting.
*
* Return(s)   : DEF_OK          Transmission successful.
*               DEF_FAIL        Transmission failed.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  CPU_BOOLEAN  TELNETs_Tx (NET_SOCK_ID   sock_id,
                                 CPU_CHAR     *pdata_buf,
                                 CPU_INT16U    data_buf_len,
                                 TELNETs_ERR  *perr)
{
    void         *tx_buf;
    CPU_INT16S    tx_buf_len;
    CPU_INT16S    tx_len;
    CPU_INT16S    tx_len_tot;
    CPU_INT08U    tx_retry_cnt;
    CPU_BOOLEAN   tx_done;
    CPU_BOOLEAN   tx_dly;
    NET_ERR       err_net;


    tx_len_tot   = 0;
    tx_retry_cnt = 0;
    tx_done      = DEF_NO;
    tx_dly       = DEF_NO;

    while ((tx_len_tot   <  data_buf_len)           &&          /* While tx tot len < data buf len ...                  */
           (tx_retry_cnt <  TELNETs_CFG_MAX_TX_TRIES) &&        /* ... & tx try     < MAX     ...                       */
           (tx_done      == DEF_NO)) {                          /* ... & tx NOT done;         ...                       */

        if (tx_dly == DEF_YES) {                                /* Dly tx, if req'd.                                    */
            TELNETs_OS_TimeDly(0, 0, 0, 10);
        }

        tx_buf     = pdata_buf    + tx_len_tot;
        tx_buf_len = data_buf_len - tx_len_tot;
        tx_len     = NetSock_TxData( sock_id,                   /* ... tx data.                                         */
                                     tx_buf,
                                     tx_buf_len,
                                     NET_SOCK_FLAG_NONE,
                                    &err_net);
        switch (err_net) {
            case NET_SOCK_ERR_NONE:
                 if (tx_len > 0) {                              /* If          tx len > 0, ...                          */
                     tx_len_tot += tx_len;                      /* ... inc tot tx len.                                  */
                     tx_dly      = DEF_NO;
                 } else {                                       /* Else dly next tx.                                    */
                     tx_dly      = DEF_YES;
                 }
                 tx_retry_cnt = 0;
                 break;

            case NET_SOCK_ERR_NOT_USED:
            case NET_SOCK_ERR_INVALID_TYPE:
            case NET_SOCK_ERR_INVALID_FAMILY:
            case NET_SOCK_ERR_INVALID_STATE:
                 tx_done = DEF_YES;
                 break;

            case NET_ERR_TX:                                    /* If transitory tx err, ...                            */
            default:
                 tx_dly = DEF_YES;                              /* ... dly next tx.                                     */
                 tx_retry_cnt++;
                 break;
        }
    }

    if (err_net != NET_SOCK_ERR_NONE) {
       *perr = TELNETs_ERR_TX;
        return (DEF_FAIL);
    }

   *perr = TELNETs_ERR_NONE;
    return (DEF_OK);
}


/*
*********************************************************************************************************
*                                           TELNETs_NVTInit()
*
* Description : (1) Initialize Network Virtual Terminal (NVT) :
*
*                   (a) Initialize session structure
*                   (b) Send system message
*                   (c) Set mode
*                   (d) Proceed with login
*
*
* Argument(s) : psession        Pointer to session structure.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE            No error.
*
*                                                                       ---- RETURNED BY TELNETs_Tx() : ---
*                               TELNETs_ERR_TX              Error transmitting.
*
* Return(s)   : DEF_OK          Initialization successful.
*               DEF_FAIL        Initialization failed.
*
* Note(s)     : (1) The server tries to operate in the character at a time mode, meaning that each
*                   character is separately transmitted and echoed by it.  For this purpose, both the
*                   echo and the suppress go ahead options are to be enabled by the server.
*********************************************************************************************************
*/

static  CPU_BOOLEAN  TELNETs_NVTInit (TELNETs_SESSION  *psession,
                                      TELNETs_ERR      *perr)
{
    CPU_BOOLEAN  rtn_val;
    CPU_SIZE_T   sys_msg_str_len;
    CPU_INT16U   i;


                                                                /* ---------------- INIT SESSION STRUCT --------------- */
    psession->rx_buf_len       =  0;
    psession->nvt_buf_len      =  0;
    psession->nvt_state        =  TELNETs_NVT_STATE_GRAPHIC;


    for (i = 0; i < TELNET_NBR_OPT_SUPPORTED; i++) {            /* Set opt.                                             */
        psession->opt[i].code                 = TELNETs_SupportedOptTbl[i];
        psession->opt[i].server_status        = TELNETs_OPT_STATUS_CMD_WONT;
        psession->opt[i].client_status        = TELNETs_OPT_STATUS_CMD_DONT;
        psession->opt[i].server_status_req_tx = DEF_NO;
        psession->opt[i].client_status_req_tx = DEF_NO;
    }


                                                                /* --------------------- TX SYS MSG ------------------- */
    sys_msg_str_len = Str_Len((CPU_CHAR *)TELNETs_SYS_MSG_STR);

    rtn_val = TELNETs_Tx((NET_SOCK_ID  )psession->sock_id,
                         (CPU_CHAR    *)TELNETs_SYS_MSG_STR,
                         (CPU_INT16U   )sys_msg_str_len,
                         (TELNETs_ERR *)perr);
    if (rtn_val == DEF_FAIL) {
       return (DEF_FAIL);
    }

                                                                /* --------------------- SET MODE --------------------- */
                                                                /* See Note #1.                                         */
    TELNETs_TxOptReq(psession, TELNETs_OPT_STATUS_CMD_WILL, TELNET_OPT_ECHO, perr);



                                                                /* ----------------------- LOGIN ---------------------- */
    rtn_val = TELNETs_NVTLogin(psession, perr);
    if (rtn_val == DEF_FAIL) {                                  /* If error ...                                         */
        return (DEF_FAIL);                                      /* ... let error message go through.                    */
    }


   *perr = TELNETs_ERR_NONE;
    return (DEF_OK);
}


/*
*********************************************************************************************************
*                                          TELNETs_NVTLogin()
*
* Description : (1) Process with user login on the system :
*
*                   (a) Request username
*                   (b) Request password
*                   (c) Validate credential
*
*
* Argument(s) : psession        Pointer to session structure.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE            No error.
*
*                                                                       ---- RETURNED BY TELNETs_Tx() : ---
*                               TELNETs_ERR_TX              Error transmitting.
*
*
* Return(s)   : DEF_OK          Login successful.
*               DEF_FAIL        Login failed.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  CPU_BOOLEAN  TELNETs_NVTLogin (TELNETs_SESSION  *psession,
                                       TELNETs_ERR      *perr)
{
    CPU_BOOLEAN  rtn_val;
    CPU_SIZE_T   tx_str_len;
    CPU_CHAR     username[TELNETs_CFG_MAX_USR_NAME_LEN];
    CPU_CHAR     password[TELNETs_CFG_MAX_PW_LEN];
    CPU_BOOLEAN  logged;
    CPU_INT08U   login_retry_cnt;


    logged          = DEF_FAIL;
    login_retry_cnt = 0;

    while ((logged          == DEF_FAIL)                    &&  /* While not logged in ...                              */
           (login_retry_cnt <  TELNETs_CFG_MAX_LOGIN_TRIES)) {  /* ... & login tries < MAX.                             */

                                                                /* ------------------- REQ USERNAME ------------------- */
        tx_str_len = Str_Len((CPU_CHAR *)TELNETs_LOGIN_STR);

        rtn_val = TELNETs_Tx((NET_SOCK_ID  )psession->sock_id,  /* Tx login msg.                                        */
                             (CPU_CHAR    *)TELNETs_LOGIN_STR,
                             (CPU_INT16U   )tx_str_len,
                             (TELNETs_ERR *)perr);
        if (rtn_val == DEF_FAIL) {
            return (DEF_FAIL);
        }

        do {
                                                                /* Rx login name.                                       */
            rtn_val = TELNETs_RxSessionData(psession, DEF_YES, perr);
            if (*perr != TELNETs_ERR_NONE) {
                return (DEF_FAIL);
            }

            TELNETs_NVTPrint(psession, DEF_YES, perr);
        } while (*perr != TELNETs_ERR_NONE_EOL_RX);

                                                                /* Get login from psession struct.                      */
        TELNETs_NVTGetBuf(psession, username, TELNETs_CFG_MAX_USR_NAME_LEN, DEF_YES, perr);
        if (*perr != TELNETs_ERR_NONE) {
            return (DEF_FAIL);
        }


                                                                /* ---------------------- REQ PW ---------------------- */
        tx_str_len = Str_Len((CPU_CHAR *)TELNETs_PW_STR);

        rtn_val = TELNETs_Tx((NET_SOCK_ID  )psession->sock_id,  /* Tx pw msg.                                           */
                             (CPU_CHAR    *)TELNETs_PW_STR,
                             (CPU_INT16U   )tx_str_len,
                             (TELNETs_ERR *)perr);
        if (rtn_val == DEF_FAIL) {
            return (DEF_FAIL);
        }


        do {
                                                                /* Rx pw.                                               */
            rtn_val = TELNETs_RxSessionData(psession, DEF_NO, perr);
            if (*perr != TELNETs_ERR_NONE) {
                return (DEF_FAIL);
            }

            TELNETs_NVTPrint(psession, DEF_NO, perr);
        } while (*perr != TELNETs_ERR_NONE_EOL_RX);

        TELNETs_Tx((NET_SOCK_ID  )psession->sock_id,
                   (CPU_CHAR    *)TELNETs_EOL_STR,
                   (CPU_INT16U   )TELNETs_EOL_STR_LEN,
                   (TELNETs_ERR *)perr);

                                                                /* Get pw from psession struct.                         */
        TELNETs_NVTGetBuf(psession, password, TELNETs_CFG_MAX_PW_LEN, DEF_YES, perr);
        if (*perr != TELNETs_ERR_NONE) {
            return (DEF_FAIL);
        }


                                                                /* --------------- VALIDATE CREDENTIALS --------------- */
        logged = TELNETs_AuthUser(username, password);

        if (logged == DEF_OK) {                                 /* If logged ...                                        */
                                                                /* ... tx welcome msg ...                               */
            tx_str_len = Str_Len((CPU_CHAR *)TELNETs_CFG_WELCOME_MSG_STR);

            rtn_val = TELNETs_Tx((NET_SOCK_ID  )psession->sock_id,
                                 (CPU_CHAR    *)TELNETs_CFG_WELCOME_MSG_STR,
                                 (CPU_INT16U   )tx_str_len,
                                 (TELNETs_ERR *)perr);
            if (rtn_val == DEF_FAIL) {
                return (DEF_FAIL);
            }

            TELNETs_NVTTxPrompt(psession, perr);                /* ... and tx cmd prompt.                               */
            if (*perr != TELNETs_ERR_NONE) {
                return (DEF_FAIL);
            }

        } else {                                                /* Else dly and retry.                                  */
            TELNETs_OS_TimeDly(0, 0, 0, TELNETs_FAILED_LOGIN_DLY_MS);
            login_retry_cnt++;
                                                                /* Tx login failure msg.                                */
            tx_str_len = Str_Len((CPU_CHAR *)TELNETs_LOGIN_FAILURE_STR);

            rtn_val = TELNETs_Tx((NET_SOCK_ID  )psession->sock_id,
                                 (CPU_CHAR    *)TELNETs_LOGIN_FAILURE_STR,
                                 (CPU_INT16U   )tx_str_len,
                                 (TELNETs_ERR *)perr);
            if (rtn_val == DEF_FAIL) {
                return (DEF_FAIL);
            }
        }
    }

    return (logged);
}


/*
*********************************************************************************************************
*                                           TELNETs_NVTPrint()
*
* Description : Process received data from telnet session.
*
* Argument(s) : psession        Pointer to session structure.
*               echo            Whether or not 'echo' are allowed (see Note #3).
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE            No error.
*                               TELNETs_ERR_NONE_EOL_RX     No error, command ready to be executed.
*
* Return(s)   : void.
*
* Note(s)     : (2) The data received from the telnet session is parsed using a state machine consisting
*                   of the following states:
*
*                   (a) TELNETs_NVT_STATE_GRAPHIC
*
*                       In this state, graphic ASCII are being sent to the printer and other meaningful
*                       code have the machine be switched into another state.  This is the state the
*                       machine enters by default.
*
*                       (1) If the NVT buffer is full while processing graphic codes, the last characters
*                           are ignored until the EOL sequence is encounter.  That line is hence incomplete,
*                           and its processing is most likely going to introduce an error.  It is the
*                           developer's responsibility to ensure that TELNETs_CFG_NVT_BUF_LEN be defined with
*                           a value large enough to provide room for the longest line transmitted.
*
*                   (b) TELNETs_NVT_STATE_CR
*
*                       State entered whenever a 'CR' character is encounter in the TELNETs_NVT_STATE_GRAPHIC
*                       state.  From there, you should either have a 'LF' following next (end of line), or a
*                       NUL meaning a 'CR' alone was intended.
*
*                       (1) However, some telnet client transmit 'CR NUL' at the end of a line.  Hence,
*                           this implementation also accept this sequence as an EOL marker.  Note that
*                           this 'CR NUL' is echoed to the client as 'CR LF'.
*
*                   (c) TELNETs_NVT_STATE_IAC
*
*                       State entered when an Interpret as Command character ('255') is found in the
*                       TELNETs_NVT_STATE_GRAPHIC state.
*
*                   (d) TELNETs_NVT_STATE_OPTION
*
*                       The machine enters this state when an option verb follows the IAC command (DO,
*                       DON'T, WILL, WON'T).  Appropriate action is then taken to either response to
*                       a request or confirm a reply.
*
*                   (e) TELNETs_NVT_STATE_CODE
*
*                       When the character following the IAC is neither another IAC nor an option verb,
*                       it is considered as being a defined telnet command, and this state deals with
*                       their meaning.
*
*               (3)     Echoing of received data is performed only when the echo option (TELNET_OPT_ECHO)
*                       is enabled, and when the function's 'echo' parameter is passed DEF_YES.
*********************************************************************************************************
*/

static  void  TELNETs_NVTPrint (TELNETs_SESSION  *psession,
                                CPU_BOOLEAN       echo,
                                TELNETs_ERR      *perr)
{
    TELNETs_NVT_STATE   state;
    CPU_INT32U          rd_ix;
    CPU_INT32U          wr_ix;
    CPU_INT08U          cur_char;
    TELNETs_OPT        *popt_echo;
    TELNETs_ERR         err_telnets;
    CPU_CHAR           *p_cmd;
    CPU_CHAR            bs_cmd[TELNETs_BS_CHAR_LEN + TELNETs_WS_CHAR_LEN];
    CPU_BOOLEAN         bs_pressed;


    state      = psession->nvt_state;
    rd_ix      = 0;
    wr_ix      = psession->nvt_buf_len;
    bs_pressed = DEF_NO;
   *perr       = TELNETs_ERR_NONE;

    while ( rd_ix < psession->rx_buf_len    &&
           *perr != TELNETs_ERR_NONE_EOL_RX) {

        cur_char = psession->rx_buf[rd_ix];
        switch (state) {
            case TELNETs_NVT_STATE_GRAPHIC:                     /* See Note 2a.                                         */
                                                                /* ------------------ USASCII GRAPHIC ----------------- */
                 if (cur_char >= TELNET_ASCII_GRAPHIC_LOWER &&
                         cur_char <= TELNET_ASCII_GRAPHIC_HIGHER) {
                                                                /* See Note 2a1.                                */
                     if (wr_ix < TELNETs_CFG_NVT_BUF_LEN) {     /* If NVT buf not full ...                      */
                         psession->nvt_buf[wr_ix] = cur_char;   /* ... wr char.                                 */
                         wr_ix++;
                     }

                 } else {
                     switch (cur_char) {
                                                                /* ------------------ REQUIRED CODES ------------------ */
                         case ASCII_CHAR_CARRIAGE_RETURN:       /* Cur char is 'CR'.                                    */
                              state = TELNETs_NVT_STATE_CR;
                              break;

                         case ASCII_CHAR_LINE_FEED:             /* Cur char is 'LF'.                                    */
                              break;                            /* Do nothing.                                          */

                         case ASCII_CHAR_NULL:                  /* Cur char is 'NULL'.                                  */
                              break;                            /* Do nothing.                                          */

                                                                /* --------------------- IAC CODE --------------------- */
                         case TELNETs_OPT_STATUS_CMD_IAC:
                             state = TELNETs_NVT_STATE_IAC;
                             break;

                         case ASCII_CHAR_BACKSPACE:             /*Moves the print head 1 char pos towards left margin.  */
                             if (psession->nvt_buf_len > 0) {
                                 bs_pressed = DEF_YES;
                                 psession->nvt_buf_len--;
                                 wr_ix--;
                             }
                             break;

                                                                /* -------------------- OTHER CODE -------------------- */
                         case ASCII_CHAR_BELL:                  /* Audible or visible signal without moving the  head.  */
                         case ASCII_CHAR_CHARACTER_TABULATION:  /* Moves the printer to the next horizontal tab stop.   */
                         case ASCII_CHAR_LINE_TABULATION:       /* Moves the printer to the next vertical   tab stop.   */
                         case ASCII_CHAR_FORM_FEED:             /* Moves to top of the next page, keep horizontal.      */
                             break;                             /* Do nothing.                                          */

                         default:
                             break;
                     }
                 }

                 rd_ix++;
                 break;

            case TELNETs_NVT_STATE_CR:                          /* See Note 2b.                                         */
                 switch(cur_char) {
                     case ASCII_CHAR_LINE_FEED:
                     case ASCII_CHAR_NULL:                      /* See Note 2b1.                                        */
                          psession->nvt_buf[wr_ix++] = ASCII_CHAR_CARRIAGE_RETURN;
                          psession->nvt_buf[wr_ix++] = ASCII_CHAR_LINE_FEED;
                          psession->nvt_buf[wr_ix]   = (CPU_CHAR)0;

                          TELNETs_TRACE_DBG(("Line: %s\n\r", psession->nvt_buf));
                         *perr = TELNETs_ERR_NONE_EOL_RX;
                          break;

                     default:                                   /* Should never happen.                                 */
                          break;
                 }

                 rd_ix++;
                 state = TELNETs_NVT_STATE_GRAPHIC;
                 break;

            case TELNETs_NVT_STATE_IAC:                         /* See Note #2c.                                        */
                 switch(cur_char) {
                     case TELNETs_OPT_STATUS_CMD_WILL:
                     case TELNETs_OPT_STATUS_CMD_WONT:
                     case TELNETs_OPT_STATUS_CMD_DO:
                     case TELNETs_OPT_STATUS_CMD_DONT:
                          psession->rx_opt_status_cmd = (TELNETs_OPT_STATUS_CMD)cur_char;
                          rd_ix++;
                          state = TELNETs_NVT_STATE_OPTION;
                          break;

                     case TELNETs_OPT_STATUS_CMD_IAC:               /* Escape IAC, second should be displayed.          */
                          if (wr_ix < TELNETs_CFG_NVT_BUF_LEN) {    /* If NVT buf not full ...                          */
                                                                    /* ... wr char.                                     */
                              psession->nvt_buf[wr_ix] = cur_char;
                              wr_ix++;
                          }

                          rd_ix++;
                          state = TELNETs_NVT_STATE_GRAPHIC;
                          break;

                     default:                                       /* Presume next char is a code.                     */
                          state = TELNETs_NVT_STATE_CODE;
                          break;
                 }

                 break;

            case TELNETs_NVT_STATE_OPTION:                      /* See Note #2d.                                        */
                 psession->rx_opt_code = cur_char;
                 TELNETs_TRACE_DBG(("Option: %u; Command: %u\n\r",
                                   (unsigned int)psession->rx_opt_code,
                                   (unsigned int)psession->rx_opt_status_cmd));

                 TELNETs_RxOptHandler(psession,
                                      psession->rx_opt_status_cmd,
                                      psession->rx_opt_code,
                                     &err_telnets);

                 rd_ix++;
                 state = TELNETs_NVT_STATE_GRAPHIC;
                 break;

            case TELNETs_NVT_STATE_CODE:                        /* See Note 2e.                                         */
                 switch (cur_char) {
                     case TELNETs_OPT_STATUS_CMD_EC:            /* Erase char.                                          */
                          if (psession->nvt_buf_len > 0) {
                              psession->nvt_buf_len--;
                              wr_ix--;
                          }
                          break;

                     case TELNETs_OPT_STATUS_CMD_EL:            /* Erase line.                                          */
                          if (psession->nvt_buf_len > 0) {
                              psession->nvt_buf_len = 0;
                              wr_ix                 = 0;
                          }
                          break;

                     case TELNETs_OPT_STATUS_CMD_NOP:
                     case TELNETs_OPT_STATUS_CMD_DM:
                     case TELNETs_OPT_STATUS_CMD_BRK:
                     case TELNETs_OPT_STATUS_CMD_IP:
                     case TELNETs_OPT_STATUS_CMD_AO:
                     case TELNETs_OPT_STATUS_CMD_AYT:
                     case TELNETs_OPT_STATUS_CMD_GA:
                     default:
                          break;                                /* Unsupported / no opt cmd's, do nothing.              */
                 }

                 rd_ix++;
                 state = TELNETs_NVT_STATE_GRAPHIC;
                 break;

            default:                                            /* Should never happen.                                 */
                 break;
        }
    }


                                                                /* ---------------------- TX ECHO --------------------- */
    popt_echo = TELNETs_GetOpt(psession, TELNET_OPT_ECHO);      /* See Note #3.                                         */
    if (popt_echo != (TELNETs_OPT *)0) {
        if (popt_echo->server_status == TELNETs_OPT_STATUS_CMD_WILL  &&
            echo                     == DEF_YES) {
            if (wr_ix > psession->nvt_buf_len) {
                TELNETs_Tx((NET_SOCK_ID  ) psession->sock_id,
                           (CPU_CHAR    *)(psession->nvt_buf + psession->nvt_buf_len),
                           (CPU_INT16U   ) wr_ix - psession->nvt_buf_len,
                           (TELNETs_ERR *)&err_telnets);
            }

            if (bs_pressed == DEF_YES) {                        /* If backspace pressed,                     ...        */
                p_cmd =  &bs_cmd[0];
               (void)Str_Copy_N(p_cmd, (const CPU_CHAR *)TELNETs_BS_CHAR, TELNETs_BS_CHAR_LEN + TELNETs_WS_CHAR_LEN);
               (void)Str_Cat_N( p_cmd, (const CPU_CHAR *)TELNETs_WS_CHAR, TELNETs_WS_CHAR_LEN);

                TELNETs_Tx((NET_SOCK_ID  ) psession->sock_id,   /* ... replace previous char by a whitespace ...        */
                           (CPU_CHAR    *) p_cmd,
                           (CPU_INT16U   )(TELNETs_BS_CHAR_LEN + TELNETs_WS_CHAR_LEN),
                           (TELNETs_ERR *)&err_telnets);

                TELNETs_Tx((NET_SOCK_ID  ) psession->sock_id,   /* ... & place the cursor before the whitespace.        */
                           (CPU_CHAR    *) TELNETs_BS_CHAR,
                           (CPU_INT16U   ) TELNETs_BS_CHAR_LEN,
                           (TELNETs_ERR *)&err_telnets);
            }
        }
    }


                                                                /* Copy remaining rx_buf at beginning.                  */
    if (rd_ix < psession->rx_buf_len) {
        Mem_Copy(psession->rx_buf, psession->rx_buf + rd_ix, psession->rx_buf_len - rd_ix);
    }

    psession->rx_buf_len  = psession->rx_buf_len - rd_ix;
    psession->nvt_buf_len = wr_ix;
    psession->nvt_state   = state;
}


/*
*********************************************************************************************************
*                                          TELNETs_NVTTxPrompt()
*
* Description : Print the command prompt on the NVT.
*
* Argument(s) : psession        Pointer to session structure.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                                                                       ----- RETURNED BY TELNETs_Tx() : -----
*                               TELNETs_ERR_NONE            No error.
*                               TELNETs_ERR_TX              Error transmitting.
*
* Return(s)   : none.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  void  TELNETs_NVTTxPrompt (TELNETs_SESSION  *psession,
                                   TELNETs_ERR      *perr)
{
    CPU_SIZE_T  prompt_len;


    prompt_len = Str_Len((CPU_CHAR *)TELNETs_PROMPT_STR);

    TELNETs_Tx((NET_SOCK_ID  )psession->sock_id,
               (CPU_CHAR    *)TELNETs_PROMPT_STR,
               (CPU_INT16U   )prompt_len,
               (TELNETs_ERR *)perr);
}


/*
*********************************************************************************************************
*                                          TELNETs_NVTGetBuf()
*
* Description : Copy NVT buf into parameter dest_buf, appending the final NULL character.
*
* Argument(s) : psession        Pointer to session structure.
*               dest_buf        Pointer to destination buffer to receive NVT buffer copy.
*               dest_buf_len    Length of  destination buffer.
*               remove_eol      Whether or not to remove the EOL termination characters.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE            No error.
*                               TELNETs_ERR_NULL_PTR        Pointer to destination buffer NULL.
*                               TELNETs_ERR_LEN_ZERO        Destination buffer length of zero.
*
* Return(s)   : none.
*
* Note(s)     : (1) Buffer copy terminates when :
*
*                   (a) Destination buffer pointer is passed NULL pointers.
*                       (1) No buffer copy performed.
*
*                   (b) Entire source copied into destination buffer.
*                       (1) Termination NULL character appended to destination buffer.
*********************************************************************************************************
*/

static  void  TELNETs_NVTGetBuf (TELNETs_SESSION  *psession,
                                 CPU_CHAR         *dest_buf,
                                 CPU_INT16U        dest_buf_len,
                                 CPU_BOOLEAN       remove_eol,
                                 TELNETs_ERR      *perr)
{
    CPU_CHAR  *peol;


    if (dest_buf == (CPU_CHAR *)0) {                            /* Rtn if dest_buf ptr(s) NULL.                         */
       *perr = TELNETs_ERR_NULL_PTR;
        return;
    }

    if (dest_buf_len == 0) {                                    /* Rtn if dest_buf len equals zero.                     */
       *perr = TELNETs_ERR_LEN_ZERO;
        return;
    }

    if (psession->nvt_buf_len >= dest_buf_len) {                /* Rtn if dest_buf less than NVT len.                   */
       *perr = TELNETs_ERR_BUF_TOO_SMALL;
        return;
    }


    if (psession->nvt_buf_len == 0) {                           /* If NVT buf empty ...                                 */
       *dest_buf = (CPU_CHAR)0;                                 /* ... copy termination char and rtn.                   */
       *perr = TELNETs_ERR_NONE;
        return;
    }


                                                                /* ------------------- COPY NVT BUF ------------------- */
    Mem_Copy((void     *)dest_buf,
             (void     *)psession->nvt_buf,
             (CPU_SIZE_T)psession->nvt_buf_len);

    dest_buf[psession->nvt_buf_len] = (CPU_CHAR)0;              /* Append termination NULL char.                        */


                                                                /* -------------- REMOVING EOL DELIMITER -------------- */
    if (remove_eol == DEF_YES) {
        peol = Str_Str((CPU_CHAR *)dest_buf,
                       (CPU_CHAR *)TELNETs_EOL_STR);
        if (peol != (CPU_CHAR *)0) {
            *peol = (CPU_CHAR)0;
        }
    }

                                                                /* ------------------ UPDATE NVT BUF ------------------ */
    psession->nvt_buf_len = 0;


   *perr = TELNETs_ERR_NONE;
}


/*
*********************************************************************************************************
*                                           TELNETs_NVTTerminate()
*
* Description : Terminate Network Virtual Terminal (NVT)
*
* Argument(s) : psession        Pointer to session structure.
*
* Return(s)   : DEF_OK          Termination successful.
*               DEF_FAIL        Termination failed.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static CPU_BOOLEAN  TELNETs_NVTTerminate (TELNETs_SESSION  *psession)
{
    psession->sock_id = (NET_SOCK_ID)NET_SOCK_ID_NONE;

#if (TELNETs_CFG_FS_EN == DEF_ENABLED)
    psession->pcur_working_dir = (void *)0;
#endif

    return (DEF_OK);
}


/*
*********************************************************************************************************
*                                              TELNETs_Cmd()
*
* Description : (1) Process the received command line :
*
*                   (a) Handle internal command
*                   (b) Handle external command, if necessary
*
*
* Arguments   : pcmd_line       Pointer to command line.
*               psession        Pointer to telnet session structure.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                                                                       --------- RETURNED BY TELNETs_CmdHandlerInt() : ---------
*                                                                       ------------ OR BY TELNETs_CmdHandlerExt() : ------------
*                               TELNETs_ERR_NONE                No error.
*                               TELNETs_ERR_CMD_PROCESS         Error processing command.
*                               TELNETs_ERR_CMD_EXEC            Error executing  command.
*
* Return(s)   : TELNETs_CMDPROCESS_ERR,        if an error occurred.
*
*               Command specific return value, otherwise.
*
* Note(s)     : (1) The function first look for a match in the internal telnet command.  If co such
*                   command if found, TELNETs_CmdHandlerInt() returns TELNETs_ERR_CMD_PROCESS, and
*                   the external command handler comes in.
*********************************************************************************************************
*/

static  CPU_INT16S  TELNETs_Cmd (CPU_CHAR         *pcmd_line,
                                 TELNETs_SESSION  *psession,
                                 TELNETs_ERR      *perr)
{
    CPU_INT16S   ret_val;
    NET_SOCK_ID  sock;


   (void)pcmd_line;                                             /* Prevent 'variable unused' compiler warning.          */

    sock = psession->sock_id;

                                                                /* ------------------ HANDLE INT CMD ------------------ */
    ret_val = TELNETs_CmdHandlerInt((CPU_CHAR      *) psession->nvt_buf,
                                    (void          *) psession->pcur_working_dir,
                                    (CPU_BOOLEAN   *)&psession->session_active,
                                    (void          *)&sock,
                                    (TELNET_OUT_FNCT)&TELNETs_OutFnct,
                                    (TELNETs_ERR   *) perr);

                                                                /* ------------------ HANDLE EXT CMD ------------------ */
    if (*perr == TELNETs_ERR_CMD_PROCESS) {                     /* See Note #1.                                         */
    ret_val = TELNETs_CmdHandlerExt((CPU_CHAR      *) psession->nvt_buf,
                                    (void          *) psession->pcur_working_dir,
                                    (CPU_BOOLEAN   *)&psession->session_active,
                                    (void          *)&sock,
                                    (TELNET_OUT_FNCT)&TELNETs_OutFnct,
                                    (TELNETs_ERR   *) perr);
    }

    return (ret_val);
}


/*
*********************************************************************************************************
*                                              TELNETs_CmdHandlerInt()
*
* Description : Process received internal command.
*
* Arguments   : pcmd_line       Pointer to command line.
*               pcwd            Pointer to current working directory.
*               psession_active Pointer to variable indicating whether the session is active or not.
*               pout_opt        Pointer to output function optional parameter.
*               pout_fnct       Pointer to output function.
*               perr            Pointer to variable that will receive the return error code from this
*                               function :
*
*                               TELNETs_ERR_NONE                No error.
*                               TELNETs_ERR_CMD_PROCESS         Error processing command (command NOT found).
*                               TELNETs_ERR_CMD_EXEC            Error executing  command.
*
* Return(s)   : TELNETs_CMDPROCESS_ERR,        if an error occurred.
*
*               Command specific return value, otherwise.
*
* Note(s)     : (1) This implementation only support the 'logout' internal command.
*********************************************************************************************************
*/

static  CPU_INT16S  TELNETs_CmdHandlerInt (CPU_CHAR         *pcmd_line,
                                           void             *pcwd,
                                           CPU_BOOLEAN      *psession_active,
                                           void             *pout_opt,
                                           TELNET_OUT_FNCT   pout_fnct,
                                           TELNETs_ERR      *perr)
{
    CPU_INT16S  cmp;
    CPU_INT16S  ret_val;


   (void)pcwd;                                                  /* Prevent 'variable unused' compiler warnings.         */
   (void)pout_opt;
   (void)pout_fnct;

    cmp = Str_Cmp(TELNETs_INT_CMD_LOGOUT, pcmd_line);

    if (cmp == 0) {                                             /* If cmd is 'logout' ...                               */
       *psession_active = DEF_NO;                               /* ... terminate the session.                           */
        ret_val = TELNETs_CMDPROCESS_ERR_NONE;
       *perr    = TELNETs_ERR_NONE;

    } else {                                                    /* Else ...                                             */
        ret_val = TELNETs_CMDPROCESS_ERR;                       /* ... cmd not found.                                   */
       *perr    = TELNETs_ERR_CMD_PROCESS;
    }

    return (ret_val);
}


/*
*********************************************************************************************************
*                                            TELNETs_GetOpt()
*
* Description : Get the telnet option structure.
*
* Argument(s) : psession        Pointer to session structure.
*               opt_code        Option code requested.
*
* Return(s)   : Pointer to a TELNETs_OPT    if successful;
*               NULL                        if option not supported.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  TELNETs_OPT  *TELNETs_GetOpt (TELNETs_SESSION  *psession,
                                      CPU_INT08U        opt_code)
{
    TELNETs_OPT  *popt;
    CPU_INT16U    i;


                                                                /* ---------------- GET CUR OPT STATUS ---------------- */
    popt = (TELNETs_OPT *)0;
    for (i = 0; i < TELNET_NBR_OPT_SUPPORTED; i++) {
        if (opt_code == psession->opt[i].code) {
            popt = &psession->opt[i];
            break;
        }
    }

    return (popt);
}


/*
*********************************************************************************************************
*                                            TELNETs_OutFnct()
*
* Description : Output function used by command to transmit data to Telnet session.
*
* Argument(s) : pbuf            Pointer to buffer containing data to send.
*               buf_len         Length of buffer.
*               psock_id        Pointer to socket id.
*
* Return(s)   : Number of positive data octets transmitted, if NO errors.
*               TELNETs_SHELL_ERR_TX,                       otherwise.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  CPU_INT16S  TELNETs_OutFnct (CPU_CHAR   *pbuf,
                                     CPU_INT16U  buf_len,
                                     void       *psock_id)
{
    NET_SOCK_ID  sock;
    CPU_INT16S   ret_val;
    TELNETs_ERR  err;


    sock = *((NET_SOCK_ID *)psock_id);

    TELNETs_Tx(sock, pbuf, buf_len, &err);
    if (err != TELNETs_ERR_NONE) {
        ret_val = TELNETs_SHELL_ERR_TX;
    } else {
        ret_val = buf_len;
    }

    return (ret_val);
}
