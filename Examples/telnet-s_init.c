/*
*********************************************************************************************************
*                                            EXAMPLE CODE
*
*               This file is provided as an example on how to use Micrium products.
*
*               Please feel free to use any application code labeled as 'EXAMPLE CODE' in
*               your application products.  Example code may be used as is, in whole or in
*               part, or may be used as a reference only. This file can be modified as
*               required to meet the end-product requirements.
*
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*
*                                            TELNET Server
*
*
* Filename : telnet-s_init.c
* Version  : V1.06.00
*********************************************************************************************************
* Note(s)  : (1) This example show how intialize the TELNET server in standard or secure mode.
*                It includes also a simple implementation of the uc/TELNETs callBack.
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*********************************************************************************************************
*                                            INCLUDE FILES
*********************************************************************************************************
*********************************************************************************************************
*/

#include  <Source/telnet-s.h>
#include  <telnet-s_cfg.h>


/*
*********************************************************************************************************
*********************************************************************************************************
*                                            LOCAL DEFINES
*********************************************************************************************************
*********************************************************************************************************
*/

#define  SERVER_CERT_DER        "\\server-cert.der"
#define  SERVER_KEY_PEM         "\\server-key.pem"

#define  APP_TELNETS_USERNAME    "admin"
#define  APP_TELNETS_PWD         "password"
#define  APP_TELNET_CMD_TEST     "test"
#define  APP_TELNET_SUCCESS_STR  "\r\ntest command recognized. This is a simple example.\r\n\r\n"
#define  APP_TELNET_FAILURE_STR  "Command not found.\r\n\r\n"

#define  APP_TELNET_IP_FAMILY    NET_SOCK_ADDR_FAMILY_IP_V4


/*
*********************************************************************************************************
*                                          AppTELNETs_Init()
*
* Description : Initialize the TELNET server.
*
* Argument(s) : none.
*
* Return(s)   : DEF_FAIL,   Operation failed.
*               DEF_OK,     Operation is successful
*
* Note(s)     : none.
*********************************************************************************************************
*/

CPU_BOOLEAN AppTELNETs_Init (void)
{
    CPU_BOOLEAN           init;
    NET_SOCK_ADDR_FAMILY  ip_family;


    ip_family = APP_TELNET_IP_FAMILY;                           /* Choose IP Family.                                    */

    init = TELNETs_Init(&ip_family, DEF_NULL);                  /* Initialize TELNET in non-secure mode.                */
    if (init == DEF_OK) {
        printf("Init successful\n\r");
    } else {
        printf("Init failed\n\r");
    }

    return (init);
}


/*
*********************************************************************************************************
*                                          TELNETs_AuthUser()
*
* Description : Telnet server callback to authenticate a user during connection request.
*
* Argument(s) : user_name   Pointer to a string that contains the username.
*
*               pw          Pointer to a string that contains the password.
*
* Return(s)   : DEF_OK,   Authentication success.
*
*               DEF_FAIL, Connection is refused.
*
* Note(s)     : none.
*********************************************************************************************************
*/

CPU_BOOLEAN  TELNETs_AuthUser (CPU_CHAR  *user_name,
                               CPU_CHAR  *pw)
{
    if ((Str_Cmp(APP_TELNETS_USERNAME, user_name) == 0) &&              /* Validate username and password.              */
        (Str_Cmp(APP_TELNETS_PWD, pw)             == 0)) {
        return (DEF_OK);                                                /* DEF_OK,   Authentication success             */
    }

    return (DEF_FAIL);                                                  /* DEF_FAIL, Connection is refused.             */
}


/*
*********************************************************************************************************
*                                        TELNETs_CmdHandlerExt()
*
* Description : Telnet server callback to execute external command.
*
* Argument(s) : pcmd_line           Pointer to a string that contains the command line received.
*
*               pcwd                Pointer to the current working directory.
*
*               psession_active     Active session or not.
*
*               pout_opt            Pointer to output option.
*
*               pout_fnct           Pointer to the output function.
*
*               perr                Pointer to variable that will receive the return error code from this:
*
*                                       TELNETs_ERR_NONE
*                                       TELNETs_ERR_CMD_EXEC
*
* Return(s)   : Command specific return value.
*
* Note(s)     : none.
*********************************************************************************************************
*/

CPU_INT16S  TELNETs_CmdHandlerExt (CPU_CHAR         *pcmd_line,
                                   void             *pcwd,
                                   CPU_BOOLEAN      *psession_active,
                                   void             *pout_opt,
                                   TELNET_OUT_FNCT   pout_fnct,
                                   TELNETs_ERR      *perr)
{
    CPU_INT16S           rtn;


    if (Str_Cmp(APP_TELNET_CMD_TEST, pcmd_line) == 0) {         /* Check the command.                                   */
                                                                /* If the test command is recognized...                 */
        pout_fnct(APP_TELNET_SUCCESS_STR, sizeof(APP_TELNET_SUCCESS_STR), pout_opt);
        rtn = sizeof(APP_TELNET_SUCCESS_STR);
       *perr = TELNETs_ERR_NONE;
    } else {
                                                                /* If no command is recognized...                       */
        pout_fnct(APP_TELNET_FAILURE_STR, sizeof(APP_TELNET_FAILURE_STR), pout_opt);
        rtn = DEF_NULL;
       *perr = TELNETs_ERR_CMD_EXEC;
    }

     return (rtn);
}
