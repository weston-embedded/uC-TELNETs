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
*                                   TELNET SERVER CMD SOURCE CODE
*
* Filename : telnet-s_shell.c
* Version  : V1.06.00
*********************************************************************************************************
* Note(s)  : (1) Assumes the following versions (or more recent) of software modules are included in
*                the project build :
*          
*                (a) uC/TCP-IP V3.00.00
*                (b) uC/OS-II  V2.90.00 or
*                    uC/OS-III V3.03.01
*                (c) uC/Shell  V1.03.01
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*********************************************************************************************************
*                                             INCLUDE FILES
*********************************************************************************************************
*********************************************************************************************************
*/

#define  MICRIUM_SOURCE
#define  TELNETs_CMD_MODULE

#include  "../Source/telnet-s.h"
#include  "telnet-s_shell.h"


/*
*********************************************************************************************************
*********************************************************************************************************
*                                            LOCAL DEFINES
*********************************************************************************************************
*********************************************************************************************************
*/


#define  TELNETs_CMD_DFLT_USER         ("DUT")
#define  TELNETs_CMD_DFLT_PASSWORD     ("micrium")


/*
*********************************************************************************************************
*********************************************************************************************************
*                                          LOCAL DATA TYPES
*********************************************************************************************************
*********************************************************************************************************
*/

typedef  struct telnets_cmd_output {
    TELNET_OUT_FNCT   OutFnct;
    void             *OutOpt_Ptr;
} TELNETs_CMD_OUTPUT;


/*
*********************************************************************************************************
*********************************************************************************************************
*                                       LOCAL GLOBAL VARIABLES
*********************************************************************************************************
*********************************************************************************************************
*/

CPU_CHAR  UserName[TELNETs_CFG_MAX_USR_NAME_LEN];
CPU_CHAR  Password[TELNETs_CFG_MAX_PW_LEN];


/*
*********************************************************************************************************
*********************************************************************************************************
*                                      LOCAL FUNCTION PROTOTYPES
*********************************************************************************************************
*********************************************************************************************************
*/

static  CPU_INT16S  TELNETsShell_Output (CPU_CHAR    *p_buf,
                                         CPU_INT16U   buf_len,
                                         void        *p_opt);


/*
*********************************************************************************************************
*                                          TELNETsSHELL_Init()
*
* Description : (1) Initialize Telnet implmentation with uC/Shell:
*
*                       (a) Set Telnet User and password for the authentication module.
*
*
* Argument(s) : user_name   Pointer to a string that contain the login username.
*
*               password    Pointer to a string that contain the login password.
*
*               ip_type     Value of the IP version (IPv4/IPv6) to use for the TELNET server.
*
*               p_err       is a pointer to an error code which will be returned to your application:
*
*                             TEMPLATE_TEST_ERR_NONE            No error.
*
*                             TEMPLATE_TEST_ERR_SHELL_INIT    Command table not added to uC-Shell
*
* Return(s)   : none.
*
* Note(s)     : none.
*********************************************************************************************************
*/

void  TELNETsShell_Init (CPU_CHAR  *user_name,
                         CPU_CHAR  *password)
{

                                                                /* Set user & password for Authentication mechanism.    */
    if (user_name[0] != ASCII_CHAR_NULL) {
        Str_Copy_N(UserName, user_name, TELNETs_CFG_MAX_USR_NAME_LEN);
    } else {
        Str_Copy_N(UserName, TELNETs_CMD_DFLT_USER, TELNETs_CFG_MAX_USR_NAME_LEN);
    }

    if (password[0] != ASCII_CHAR_NULL) {
        Str_Copy_N(Password, password, TELNETs_CFG_MAX_PW_LEN);
    } else {
        Str_Copy_N(Password, TELNETs_CMD_DFLT_PASSWORD, TELNETs_CFG_MAX_PW_LEN);
    }
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
    if ((Str_Cmp(UserName, user_name) == 0) &&
        (Str_Cmp(Password, pw)        == 0)) {
        return (DEF_OK);
    }

    return (DEF_FAIL);
}


/*
*********************************************************************************************************
*                                        TELNETs_CmdHandlerExt()
*
* Description : Telnet server callback to execute external command. The command received is passed to uC/Shell.
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
    TELNETs_CMD_OUTPUT   outparam;
    SHELL_CMD_PARAM      param;
    SHELL_ERR            err;


    outparam.OutFnct    = pout_fnct;
    outparam.OutOpt_Ptr = pout_opt;
    param.pout_opt      = &outparam;


    rtn = Shell_Exec( pcmd_line,
                      TELNETsShell_Output,
                     &param,
                     &err);
    if (rtn > 0) {
       *perr = TELNETs_ERR_NONE;

    } else {
        pout_fnct("Shell Exec Error\n\r\n\r", 20 ,pout_opt);
       *perr = TELNETs_ERR_CMD_EXEC;
    }

    return (rtn);
}


/*
*********************************************************************************************************
*                                          TELNETsCmd_Output()
*
* Description : Callback function used by uC-Shell to output data via a Telnet session.
*
* Argument(s) : p_buf       Pointer to the buffer that contains the string to send via telnet.
*
*               buf_len     Data length to send.
*
*               p_opt       Pointer to output option/parameter.
*
* Return(s)   : Number of byte send by Telnet.
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  CPU_INT16S  TELNETsShell_Output (CPU_CHAR    *p_buf,
                                         CPU_INT16U   buf_len,
                                         void        *p_opt)
{
    TELNETs_CMD_OUTPUT  *poutparam;
    CPU_INT16S           rtn_val;


    poutparam = (TELNETs_CMD_OUTPUT *)p_opt;

    rtn_val   =  poutparam->OutFnct(p_buf, buf_len, poutparam->OutOpt_Ptr);

    return (rtn_val);
}
