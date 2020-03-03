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
*                                          Micrium uC/OS-II
*
* Filename : telnet-s_os.c
* Version  : V1.06.00
*********************************************************************************************************
* Note(s)  : (1) Assumes uC/OS-II V2.86 (or more recent version) is included in the project build.
*
*            (2) REQUIREs the following uC/OS-II feature(s) to be ENABLED :
*
*                    --------- FEATURE --------    -- MINIMUM CONFIGURATION FOR TELNETs/OS PORT --
*
*                (a) Tasks
*                    (1) OS_TASK_DEL_EN            Enabled
*                    (2) OS_TASK_SUSPEND_EN        Enabled
*
*                (b) Time Delay
*                    (1) OS_TIME_DLY_HMSM_EN       Enabled
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
#include  <Source/ucos_ii.h>                                    /* See this 'telnet-s_os.c  Note #1'.                   */



/*
*********************************************************************************************************
*                                     LOCAL CONFIGURATION ERRORS
*********************************************************************************************************
*/

                                                                /* See this 'telnet-s_os.c  Note #1'.                   */
#if     (OS_VERSION < 286u)
#error  "OS_VERSION [SHOULD be >= V2.86]"
#endif



                                                                /* See this 'telnet-s_os.c  Note #2a'.                  */
#if     (OS_TASK_DEL_EN < 1u)
#error  "OS_TASK_DEL_EN illegally #define'd in 'os_cfg.h' [MUST be  > 0, (see 'telnet-s_os.c  Note #2a1')]"
#endif

#if     (OS_TASK_SUSPEND_EN < 1u)
#error  "OS_TASK_SUSPEND_EN illegally #define'd in 'os_cfg.h' [MUST be  > 0, (see 'telnet-s_os.c  Note #2a2')]"
#endif



                                                                /* See this 'telnet-s_os.c  Note #2b'.                  */
#if     (OS_TIME_DLY_HMSM_EN < 1u)
#error  "OS_TIME_DLY_HMSM_EN illegally #define'd in 'os_cfg.h' [MUST be  > 0, (see 'telnet-s_os.c  Note #2b1')]"
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
#define  TELNETs_OS_SERVER_TASK_NAME        "TELNET (Server) "
#define  TELNETs_OS_SESSION_TASK_NAME       "TELNET (Session)"

#define  TELNETs_OS_OBJ_NAME_SIZE_MAX                     20    /* Maximum of ALL TELNETs object name sizes.            */


/*
*********************************************************************************************************
*********************************************************************************************************
*                                       LOCAL GLOBAL VARIABLES
*********************************************************************************************************
*********************************************************************************************************
*/

                                                                /* ------------------- TASK STACKS -------------------- */
static  OS_STK  TELNETs_OS_ServerTaskStk[TELNETs_OS_CFG_SERVER_TASK_STK_SIZE];
static  OS_STK  TELNETs_OS_SessionTaskStk[TELNETs_OS_CFG_SESSION_TASK_STK_SIZE];


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
* Argument(s) : p_data      Pointer to task initialization data (required by uC/OS-II).
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
    INT8U  os_err;


                                                                /* Create TELNET server         task.                   */
#if (OS_TASK_CREATE_EXT_EN > 0u)
    #if (OS_STK_GROWTH == 1u)
    os_err = OSTaskCreateExt((void (*)(void *)) TELNETs_OS_ServerTask,
                             (void          * ) p_data,
                                                                                                    /* Set Top-Of-Stack.    */
                             (OS_STK        * )&TELNETs_OS_ServerTaskStk[TELNETs_OS_CFG_SERVER_TASK_STK_SIZE - 1],
                             (INT8U           ) TELNETs_OS_CFG_SERVER_TASK_PRIO,
                             (INT16U          ) TELNETs_OS_CFG_SERVER_TASK_PRIO,
                             (OS_STK        * )&TELNETs_OS_ServerTaskStk[0],                        /* Set Bottom-Of-Stack. */
                             (INT32U          ) TELNETs_OS_CFG_SERVER_TASK_STK_SIZE,
                             (void          * ) 0,
                             (INT16U          ) OS_TASK_OPT_STK_CHK | OS_TASK_OPT_STK_CLR);
    #else
    os_err = OSTaskCreateExt((void (*)(void *)) TELNETs_OS_ServerTask,
                             (void          * ) p_data,
                             (OS_STK        * )&TELNETs_OS_ServerTaskStk[0],                        /* Set Top-Of-Stack.    */
                             (INT8U           ) TELNETs_OS_CFG_SERVER_TASK_PRIO,
                             (INT16U          ) TELNETs_OS_CFG_SERVER_TASK_PRIO,
                                                                                                    /* Set Bottom-Of-Stack. */
                             (OS_STK        * )&TELNETs_OS_ServerTaskStk[TELNETs_OS_CFG_SERVER_TASK_STK_SIZE - 1],/
                             (INT32U          ) TELNETs_OS_CFG_SERVER_TASK_STK_SIZE,
                             (void          * ) 0,                                                  /* No TCB extension.    */
                             (INT16U          ) OS_TASK_OPT_STK_CHK | OS_TASK_OPT_STK_CLR);
    #endif
#else
    #if (OS_STK_GROWTH == 1)
    os_err = OSTaskCreate( TELNETs_OS_ServerTask,
    os_err = OSTaskCreate((void (*)(void *)) TELNETs_OS_ServerTask,
                          (void          * ) p_data,
                                                                                                    /* Set Bottom-Of-Stack. */
                          (OS_STK        * )&TELNETs_OS_ServerTaskStk[TELNETs_OS_CFG_SERVER_TASK_STK_SIZE - 1],
                          (INT8U           ) TELNETs_OS_CFG_SERVER_TASK_PRIO);
    #else
    os_err = OSTaskCreate((void (*)(void *)) TELNETs_OS_ServerTask,
                          (void          * ) p_data,
                          (OS_STK        * )&TELNETs_OS_ServerTaskStk[0],                           /* Set Top-Of-Stack.    */
                          (INT8U           ) TELNETs_OS_CFG_SERVER_TASK_PRIO);
    #endif
#endif

    if (os_err != OS_ERR_NONE) {
        return (DEF_FAIL);
    }

#if (((OS_VERSION >= 288u) && (OS_TASK_NAME_EN   >  0u)) || \
     ((OS_VERSION <  288u) && (OS_TASK_NAME_SIZE >= TELNETs_OS_OBJ_NAME_SIZE_MAX)))
    OSTaskNameSet((INT8U  ) TELNETs_OS_CFG_SERVER_TASK_PRIO,
                  (INT8U *) TELNETs_OS_SERVER_TASK_NAME,
                  (INT8U *)&os_err);
#endif


    return (DEF_OK);
}


/*
*********************************************************************************************************
*                                       TELNETs_OS_ServerTask()
*
* Description : OS-dependent FTP server task.
*
* Argument(s) : p_data      Pointer to task initialization data (required by uC/OS-II).
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
    TELNETs_ServerTask(p_data);                                 /* Call TELNET server           task.                   */
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
* Argument(s) : p_data      Pointer to task initialization data (required by uC/OS-II).
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
    INT8U  os_err;


                                                                /* Create TELNET server session task.                   */
#if (OS_TASK_CREATE_EXT_EN > 0u)
    #if (OS_STK_GROWTH == 1u)
    os_err = OSTaskCreateExt((void (*)(void *)) TELNETs_OS_SessionTask,
                             (void          * ) p_data,
                                                                                                    /* Set Top-Of-Stack.    */
                             (OS_STK        * )&TELNETs_OS_SessionTaskStk[TELNETs_OS_CFG_SESSION_TASK_STK_SIZE - 1],
                             (INT8U           ) TELNETs_OS_CFG_SESSION_TASK_PRIO,
                             (INT16U          ) TELNETs_OS_CFG_SESSION_TASK_PRIO,
                             (OS_STK        * )&TELNETs_OS_SessionTaskStk[0],                       /* Set Bottom-Of-Stack. */
                             (INT32U          ) TELNETs_OS_CFG_SESSION_TASK_STK_SIZE,
                             (void          * ) 0,
                             (INT16U          ) OS_TASK_OPT_STK_CHK | OS_TASK_OPT_STK_CLR);
    #else
    os_err = OSTaskCreateExt((void (*)(void *)) TELNETs_OS_SessionTask,
                             (void          * ) p_data,
                             (OS_STK        * )&TELNETs_OS_SessionTaskStk[0],                       /* Set Top-Of-Stack.    */
                             (INT8U           ) TELNETs_OS_CFG_SESSION_TASK_PRIO,
                             (INT16U          ) TELNETs_OS_CFG_SESSION_TASK_PRIO,
                                                                                                    /* Set Bottom-Of-Stack. */
                             (OS_STK        * )&TELNETs_OS_SessionTaskStk[TELNETs_OS_CFG_SESSION_TASK_STK_SIZE - 1],/
                             (INT32U          ) TELNETs_OS_CFG_SESSION_TASK_STK_SIZE,
                             (void          * ) 0,                                                  /* No TCB extension.    */
                             (INT16U          ) OS_TASK_OPT_STK_CHK | OS_TASK_OPT_STK_CLR);
    #endif
#else
    #if (OS_STK_GROWTH == 1)
    os_err = OSTaskCreate((void (*)(void *)) TELNETs_OS_SessionTask,
                          (void          * ) p_data,
                                                                                                    /* Set Bottom-Of-Stack. */
                          (OS_STK        * )&TELNETs_OS_SessionTaskStk[TELNETs_OS_CFG_SESSION_TASK_STK_SIZE - 1],
                          (INT8U           ) TELNETs_OS_CFG_SESSION_TASK_PRIO);
    #else
    os_err = OSTaskCreate((void (*)(void *)) TELNETs_OS_SessionTask,
                          (void          * ) p_data,
                          (OS_STK        * )&TELNETs_OS_SessionTaskStk[0],                          /* Set Top-Of-Stack.    */
                          (INT8U           ) TELNETs_OS_CFG_SESSION_TASK_PRIO);
    #endif
#endif

    if (os_err != OS_ERR_NONE) {
        return (DEF_FAIL);
    }

#if (((OS_VERSION >= 288u) && (OS_TASK_NAME_EN   >  0u)) || \
     ((OS_VERSION <  288u) && (OS_TASK_NAME_SIZE >= TELNETs_OS_OBJ_NAME_SIZE_MAX)))
    OSTaskNameSet((INT8U  ) TELNETs_OS_CFG_SESSION_TASK_PRIO,
                  (INT8U *) TELNETs_OS_SESSION_TASK_NAME,
                  (INT8U *)&os_err);
#endif


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
    TELNETs_SessionTask(p_data);                                /* Call TELNET session          task.                   */
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
    OSTaskSuspend(OS_PRIO_SELF);                                /* Suspend TELNET server    task.                       */
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
    OSTaskDel(OS_PRIO_SELF);                                    /* Delete TELNET server session task.                   */
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

CPU_BOOLEAN  TELNETs_OS_TimeDly (INT8U  time_hr,
                                 INT8U  time_min,
                                 INT8U  time_sec,
                                 INT8U  time_ms)
{
    CPU_BOOLEAN  rtn_val;
    INT8U        os_err;


    os_err = OSTimeDlyHMSM((INT8U) time_hr,
                           (INT8U) time_min,
                           (INT8U) time_sec,
                           (INT8U) time_ms);

    if (os_err == OS_ERR_NONE) {
        rtn_val = DEF_OK;
    } else {
        rtn_val = DEF_FAIL;
    }

    return (rtn_val);
}

