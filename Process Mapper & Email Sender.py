#!/usr/bin/python

import smtplib
from email.mime.text import MIMEText
import time
import subprocess
import sys
import logging
from logging.handlers import RotatingFileHandler
import os
import psutil   # pip3 install psutil
from subprocess import PIPE, Popen


def execute_subprocess(command):
    try:
        app_log.debug("Executing command: ' {0} ' ".format(command))
        process = Popen(
            args=command,
            stdout=PIPE,
            stderr=PIPE,
            shell=True
        )
        return process.communicate()[0]
    except Exception as e:
        app_log.debug("Received error ' {0} ' during execute_subprocess for {1}".format(e, command))



def checkIfProcessRunning(processName):
    '''
    Check if there is any running process that contains the given name processName.
    '''
    # Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            # Check if process name contains the given name string.
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False


def findProcessIdByName(processName):
    '''
    Get a list of all the PIDs of a all the running process whose name contains
    the given string processName
    '''
    listOfProcessObjects = []
    # Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'create_time'])
            # Check if process name contains the given name string.
            if processName.lower() in pinfo['name'].lower():
                listOfProcessObjects.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return listOfProcessObjects


def stop_all_processes(monitor_script):
    '''
    stop all process with name "monitor_script"
    '''
    while True:
        if checkIfProcessRunning(monitor_script):
            app_log.info("Process is already running for WingS")
            for p in findProcessIdByName(monitor_script):
                app_log.info("Process is already running for WingS so executed process kill for pid " + str(p))
                # execute_subprocess("sudo kill -9 " + str(p))
                try:
                    print(str(p['pid']))
                    os.system("sudo kill %d"%(p['pid']))
                except Exception as e:
                    app_log.debug("Received error ' {0} ' during kill pid: {1}".format(e, p))
                time.sleep(1)
            time.sleep(10)
        else:
            app_log.info("No WINGs serverices are running at start")
            return True


def get_pname(id):
    p = subprocess.Popen(["ps -o cmd= {}".format(id)], stdout=subprocess.PIPE, shell=True)
    return str(p.communicate()[0])


def setup_logger(logging_level, logfile_path):
    LEVELS = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}
    logging_level = LEVELS.get((logging_level if logging_level in LEVELS.keys() else 'critical'), logging.NOTSET)
    log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
    my_handler = RotatingFileHandler(logfile_path, mode='a', maxBytes=500 * 1024 * 1024,
                                     backupCount=2, encoding=None, delay=0)
    my_handler.setFormatter(log_formatter)
    my_handler.setLevel(logging_level)
    app_log = logging.getLogger('root')
    app_log.setLevel(logging_level)
    app_log.addHandler(my_handler)
    return app_log


def prevent_duplicate_execution():
    pidfile = os.path.join(os.getcwd(), "mydaemon.pid")
    app_log.info("Get PID File for Run_WingS.py: " + str(pidfile))
    app_log.info("Get PID Name for Run_WingS.py: " + str(get_pname(str(os.getpid()))))
    app_log.info("Get File Name for Run_WingS.py: " + str(os.path.basename(__file__)))
    if os.path.exists(pidfile):
        if not os.system('ps up `cat ' + pidfile + ' ` >/dev/null'):
            pid = open(pidfile, "r").read()
            if str(os.path.basename(__file__)) in str(get_pname(pid)):
                app_log.info("Process is already running for Run_WingS.py so skipping execution")
                sys.exit(0)
    pid = str(os.getpid())
    with open(pidfile, "w+") as pfile:
        pfile.write(pid)


def send_email(content):
    # Email Content
    msg = MIMEText('\n'.join(content))
    msg['From'] = 'MumbaiWINGs@wing.local'
    msg['To'] = 'amit.hirapara81@gmail.com'
    msg['Subject'] = 'Mumbai WingS Restart'
    recipients = ['support@anvayatechnocrats.com', ]
    USER = ""
    PWD = ""

    # Send the message via our own SMTP server, but don't include the envelope header.
    # server_list = ['mx3.anvaya.com', 'mx4.anvaya.com', 'mx5.anvaya.com', 'mx6.anvaya.com', 'mx1.anvaya.com']
    server_list = ['mx3.anvaya.com']
    for _ in range(5):
        try:
            server = smtplib.SMTP(server_list[0])
            app_log.info("Connected with server : " + str(server_list[0]))
            server.set_debuglevel(1)
            server.ehlo()
            server.sendmail('kirtan.upwork@gmail.com', recipients, msg.as_string())
            app_log.info(" Email Sent!!!")
            server.quit()
            break
        except Exception as e:
            app_log.critical(
                "Received exception " + str(e) + " during connection to server " + str(
                    server_list[0]))
