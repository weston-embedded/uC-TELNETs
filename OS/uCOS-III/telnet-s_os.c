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
*                                TELNET SERVER OPERATING SYSTEM LAYER
*
*                                          Micrium uC/OS-III
*
* Filename : telnet-s_os.c
* Version  : V1.06.00
*********************************************************************************************************
* Note(s)  : (1) Assumes uC/OS-III V3.01.0 (or more recent version) is included in the project build.
*          
*            (2) REQUIREs the following uC/OS-III feature(s) to be ENABLED :
*          
*                    --------- FEATURE --------    -- MINIMUM CONFIGURATION FOR TELNETs/OS PORT --
*          
*                (a) Tasks
*                    (1) OS_CFG_TASK_DEL_EN        Enabled
*                    (2) OS_CFG_TASK_SUSPEND_EN    Enabled
*          
*                (b) Time Delay
*                    (1) OS_CFG_TIME_DLY_HMSM_EN   Enabled
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*********************************************************************************************************
*                                            INCLUDE FILES
*********************************************************************************************************
*********************************************************************************************************
*/

#include  "../../Source/telnet-s.h"
#include  <Source/os.h>                                         /* See this 'telnet-s_os.c  Note #1'.                   */


/*
*********************************************************************************************************
*********************************************************************************************************
*                                     LOCAL CONFIGURATION ERRORS
*********************************************************************************************************
*********************************************************************************************************
*/

                                                                /* See this 'telnet-s_os.c  Note #1'.                   */
#if     (OS_VERSION < 3010u)
#error  "OS_VERSION [SHOULD be >= V3.01.0]"
#endif



                                                                /* See this 'telnet-s_os.c  Note #2a'.                  */
#if     (OS_CFG_TASK_DEL_EN < 1u)
#error  "OS_CFG_TASK_DEL_EN illegally #define'd in 'os_cfg.h'               "
#error  "                                       [MUST be  > 0, (see 'telnet-s_os.c  Note #2a1')]"
#endif

#if     (OS_CFG_TASK_SUSPEND_EN < 1u)
#error  "OS_CFG_TASK_SUSPEND_EN illegally #define'd in 'os_cfg.h' [MUST be  > 0, (see 'telnet-s_os.c  Note #2a2')]"
#endif



                                                                /* See this 'telnet-s_os.c  Note #2b'.                  */
#if     (OS_CFG_TIME_DLY_HMSM_EN < 1u)
#error  "OS_CFG_TIME_DLY_HMSM_EN illegally #define'd in 'os_cfg.h' [MUST be  > 0, (see 'telnet-s_os.c  Note #2b1')]"
#endif




#ifndef  TELNETs_OS_CFG_SERVER_TASK_PRIO
#error  "TELNETs_OS_CFG_SERVER_TASK_PRIO not #define'd in 'telnet-s_cfg.h' [MUST be  >= 0u]"

#elif   (TELNETs_OS_CFG_SERVER_TASK_PRIO < 0u)
#error  "TELNETs_OS_CFG_SERVER_TASK_PRIO illegally #define'd in 'telnet-s_cfg.h' [MUST be  >= 0u]"
#endif


#ifndef  TELNETs_OS_CFG_SESSION_TASK_PRIO
#error  "TELNETs_OS_CFG_SESSION_TASK_PRIO not #define'd in 'telnet-s_cfg.h' [MUST be  >= 0u]"

#elif   (TELNETs_OS_CFG_SESSION_TASK_PRIO   < 0u)
#error  "TELNETs_OS_CFG_SESSION_TASK_PRIO illegally #define'd in 'telnet-s_cfg.h' [MUST be  >= 0u]"
#endif



#ifndef  TELNETs_OS_CFG_SERVER_TASK_STK_SIZE
#error  "TELNETs_OS_CFG_SERVER_TASK_STK_SIZE not #define'd in 'telnet-s_cfg.h' [MUST be  > 0u]"

#elif   (TELNETs_OS_CFG_SERVER_TASK_STK_SIZE < 1u)
#error  "TELNETs_OS_CFG_SERVER_TASK_STK_SIZE illegally #define'd in 'telnet-s_cfg.h' [MUST be  > 0u]"
#endif


#ifndef  TELNETs_OS_CFG_SESSION_TASK_STK_SIZE
#error  "TELNETs_OS_CFG_SESSION_TASK_STK_SIZE not #define'd in 'telnet-s_cfg.h' [MUST be  > 0u]"

#elif   (TELNETs_OS_CFG_SESSION_TASK_STK_SIZE   < 1u)
#error  "TELNETs_OS_CFG_SESSION_TASK_STK_SIZE illegally #define'd in 'telnet-s_cfg.h' [MUST be  > 0u]"
#endif



/*
*********************************************************************************************************
*********************************************************************************************************
*                                            LOCAL DEFINES
*********************************************************************************************************
*********************************************************************************************************
*/


/*
*********************************************************************************************************
*                                     OS TASK/OBJECT NAME DEFINES
*********************************************************************************************************
*/

                                                                /* -------------------- TASK NAMES -------------------- */
                                          /*           1         2 */
                                          /* 012345678901234567890 */
#define  TELNETs_OS_SERVER_TASK_NAME        "TELNET (Server)"
#define  TELNETs_OS_SESSION_TASK_NAME       "TELNET (Session)"


/*
*********************************************************************************************************
*********************************************************************************************************
*                                       LOCAL GLOBAL VARIABLES
*********************************************************************************************************
*********************************************************************************************************
*/

                                                                /* -------------------- TASK TCBs --------------------- */
static  OS_TCB   TELNETs_OS_ServerTaskTCB;
static  OS_TCB   TELNETs_OS_SessionTaskTCB;


                                                                /* ------------------- TASK STACKS -------------------- */
static  CPU_STK  TELNETs_OS_ServerTaskStk[TELNETs_OS_CFG_SERVER_TASK_STK_SIZE];
static  CPU_STK  TELNETs_OS_Session_TaskStk[TELNETs_OS_CFG_SESSION_TASK_STK_SIZE];


/*
*********************************************************************************************************
*********************************************************************************************************
*                                      LOCAL FUNCTION PROTOTYPES
*********************************************************************************************************
*********************************************************************************************************
*/

                                                                /* --------- TELNETs TASK MANAGEMENT FUNCTION --------- */
static  void  TELNETs_OS_ServerTask (void  *p_data);

                                                                /* ----- TELNETs SESSION TASK MANAGEMENT FUNCTION ----- */
static  void  TELNETs_OS_SessionTask(void  *p_data);



/*
*********************************************************************************************************
*********************************************************************************************************
*                                          TELNETs FUNCTIONS
*********************************************************************************************************
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*                                     TELNETs_OS_ServerTaskInit()
*
* Description : (1) Perform TELNET server/OS initialization :
*
*                   (a) Create TELNET server task
*
*
* Argument(s) : p_data      Pointer to task initialization data (required by uC/OS-III).
*
* Return(s)   : DEF_OK,   if server task successfully created.
*
*               DEF_FAIL, otherwise.
*
* Note(s)     : none.
*********************************************************************************************************
*/

CPU_BOOLEAN  TELNETs_OS_ServerTaskInit (void  *p_data)
{
    OS_ERR  os_err;


                                                                /* Create TELNET server             task.               */
    OSTaskCreate((OS_TCB     *)&TELNETs_OS_ServerTaskTCB,
                 (CPU_CHAR   *) TELNETs_OS_SERVER_TASK_NAME,
                 (OS_TASK_PTR ) TELNETs_OS_ServerTask,
                 (void       *) p_data,
                 (OS_PRIO     ) TELNETs_OS_CFG_SERVER_TASK_PRIO,
                 (CPU_STK    *)&TELNETs_OS_ServerTaskStk[0],
                 (CPU_STK_SIZE)(TELNETs_OS_CFG_SERVER_TASK_STK_SIZE / 10u),
                 (CPU_STK_SIZE) TELNETs_OS_CFG_SERVER_TASK_STK_SIZE,
                 (OS_MSG_QTY  ) 0u,
                 (OS_TICK     ) 0u,
                 (void       *) 0,
                 (OS_OPT      )(OS_OPT_TASK_STK_CHK | OS_OPT_TASK_STK_CLR),
                 (OS_ERR     *)&os_err);

    if (os_err != OS_ERR_NONE) {
        return (DEF_FAIL);
    }


    return (DEF_OK);
}


/*
*********************************************************************************************************
*                                       TELNETs_OS_ServerTask()
*
* Description : OS-dependent FTP server task.
*
* Argument(s) : p_data      Pointer to task initialization data (required by uC/OS-III).
*
* Return(s)   : none.
*
* Created by  : TELNETs_OS_ServerTaskInit().
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  void  TELNETs_OS_ServerTask (void  *p_data)
{
    TELNETs_ServerTask(p_data);                                 /* Call TELNET server  task body.                       */
}



/*
*********************************************************************************************************
*                                    TELNETs_OS_SessionTaskInit()
*
* Description : (1) Perform TELNET server/OS session task initialization :
*
*                   (a) Create TELNET server session task
*
*
* Argument(s) : p_data      Pointer to task initialization data (required by uC/OS-III).
*
* Return(s)   : DEF_OK,   if server task successfully created.
*
*               DEF_FAIL, otherwise.
*
* Note(s)     : none.
*********************************************************************************************************
*/

CPU_BOOLEAN  TELNETs_OS_SessionTaskInit (void  *p_data)
{
    OS_ERR  os_err;


                                                                /* Create TELNET server session     task.               */
    OSTaskCreate((OS_TCB     *)&TELNETs_OS_SessionTaskTCB,
                 (CPU_CHAR   *) TELNETs_OS_SESSION_TASK_NAME,
                 (OS_TASK_PTR ) TELNETs_OS_SessionTask,
                 (void       *) p_data,
                 (OS_PRIO     ) TELNETs_OS_CFG_SESSION_TASK_PRIO,
                 (CPU_STK    *)&TELNETs_OS_Session_TaskStk[0],
                 (CPU_STK_SIZE)(TELNETs_OS_CFG_SESSION_TASK_STK_SIZE / 10u),
                 (CPU_STK_SIZE) TELNETs_OS_CFG_SESSION_TASK_STK_SIZE,
                 (OS_MSG_QTY  ) 0u,
                 (OS_TICK     ) 0u,
                 (void       *) 0,
                 (OS_OPT      )(OS_OPT_TASK_STK_CHK | OS_OPT_TASK_STK_CLR),
                 (OS_ERR     *)&os_err);

    if (os_err != OS_ERR_NONE) {
        return (DEF_FAIL);
    }


    return (DEF_OK);
}


/*
*********************************************************************************************************
*                                      TELNETs_OS_SessionTask()
*
* Description : OS-dependent FTP server task.
*
* Argument(s) : p_data      Pointer to task initialization data (required by uC/OS-III).
*
* Return(s)   : none.
*
* Created by  : TELNETs_OS_SessionTaskInit().
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  void  TELNETs_OS_SessionTask (void  *p_data)
{
    TELNETs_SessionTask(p_data);                                /* Call TELNET session task body.                       */
}



/*
*********************************************************************************************************
*                                      TELNETs_OS_TaskSuspend()
*
* Description : Suspend the TELNET server task.
*
* Argument(s) : none.
*
* Return(s)   : none.
*
* Note(s)     : none.
*********************************************************************************************************
*/

void  TELNETs_OS_TaskSuspend (void)
{
    OS_ERR  os_err;


    OSTaskSuspend((OS_TCB *)&TELNETs_OS_ServerTaskTCB,          /* Suspend the TELNET server        task.               */
                  (OS_ERR *)&os_err);

   (void)os_err;
}


/*
*********************************************************************************************************
*                                       TELNETs_OS_TaskDelete()
*
* Description : Delete the TELNET server session task.
*
* Argument(s) : none.
*
* Return(s)   : none.
*
* Note(s)     : none.
*********************************************************************************************************
*/

void  TELNETs_OS_TaskDelete (void)
{
    OS_ERR  os_err;


    OSTaskDel((OS_TCB *)&TELNETs_OS_SessionTaskTCB,             /* Delete the TELNET server session task.               */
              (OS_ERR *)&os_err);

   (void)os_err;
}



/*
*********************************************************************************************************
*                                        TELNETs_OS_TimeDly()
*
* Description : Delay for specified time, in hours, minutes, seconds & milliseconds.
*
* Argument(s) : time_hr     Specifies the number of hours that the task will be delayed (max. is 255).
*               time_min    Specifies the number of minutes (max. 59).
*               time_sec    Specifies the number of seconds (max. 59).
*               time_ms     Specifies the number of milliseconds (max. 999).
*
* Return(s)   : DEF_OK,   if delay successfully inserted.
*
*               DEF_FAIL, otherwise.
*
* Note(s)     : none.
*********************************************************************************************************
*/

CPU_BOOLEAN  TELNETs_OS_TimeDly (CPU_INT08U  time_hr,
                                 CPU_INT08U  time_min,
                                 CPU_INT08U  time_sec,
                                 CPU_INT08U  time_ms)
{
    CPU_BOOLEAN  rtn_val;
    OS_ERR       os_err;


    OSTimeDlyHMSM((CPU_INT16U) time_hr,
                  (CPU_INT16U) time_min,
                  (CPU_INT16U) time_sec,
                  (CPU_INT32U) time_ms,
                  (OS_OPT    ) OS_OPT_TIME_HMSM_NON_STRICT,
                  (OS_ERR   *)&os_err);

    if (os_err == OS_ERR_NONE) {
        rtn_val = DEF_OK;
    } else {
        rtn_val = DEF_FAIL;
    }

    return (rtn_val);
}

