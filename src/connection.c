/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "monkey.h"
#include "http.h"
#include "plugin.h"

int mk_conn_read(int socket)
{
    int ret;
    struct client_session *cs;
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("[FD %i] Connection Handler / read", socket);
#endif

    /* Plugin hook */
    ret = mk_plugin_event_read(socket);

    switch(ret) {
    case MK_PLUGIN_RET_EVENT_OWNED:
        return MK_PLUGIN_RET_CONTINUE;
    case MK_PLUGIN_RET_EVENT_CLOSE:
        return -1;
    case MK_PLUGIN_RET_EVENT_CONTINUE:
        break; /* just return controller to invoker */
    }

    sched = mk_sched_get_thread_conf();

    cs = mk_session_get(socket);
    if (!cs) {
        /* Note: Linux don't set TCP_NODELAY socket flag by default */
        mk_socket_set_tcp_nodelay(socket);

        /* Create client */
        cs = mk_session_create(socket);
        if (!cs) {
            return -1;
        }
    }

    /* Read incomming data */
    ret = mk_handler_read(socket, cs);

    if (ret > 0) {
        if (mk_http_pending_request(cs) == 0) {
            mk_epoll_change_mode(sched->epoll_fd,
                                 socket, MK_EPOLL_WRITE);
        }
        else if (cs->body_length + 1 >= config->max_request_size) {
            /* Request is incomplete and our buffer is full,
             * close connection
             */
            mk_session_remove(socket);
            return -1;
        }
    }

    return ret;
}

int mk_conn_write(int socket)
{
    int ret = -1;
    struct client_session *cs;
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("[FD %i] Connection Handler / write", socket);
#endif

    /* Plugin hook */
    ret = mk_plugin_event_write(socket);
    switch(ret) {
    case MK_PLUGIN_RET_EVENT_OWNED:
        return MK_PLUGIN_RET_CONTINUE;
    case MK_PLUGIN_RET_EVENT_CLOSE:
        return -1;
    case MK_PLUGIN_RET_EVENT_CONTINUE:
        break; /* just return controller to invoker */
    }

#ifdef TRACE
    MK_TRACE("[FD %i] Normal connection write handling", socket);
#endif

    sched = mk_sched_get_thread_conf();
    mk_sched_update_conn_status(sched, socket, MK_SCHEDULER_CONN_PROCESS);

    /* Get node from schedule list node which contains
     * the information regarding to the current client/socket
     */
    cs = mk_session_get(socket);

    if (!cs) {
        return -1;
    }

    ret = mk_handler_write(socket, cs);

    /* if ret < 0, means that some error
     * happened in the writer call, in the
     * other hand, 0 means a successful request
     * processed, if ret > 0 means that some data
     * still need to be send.
     */
    if (ret < 0) {
        mk_request_free_list(cs);
        mk_session_remove(socket);
        return -1;
    }
    else if (ret == 0) {
        if (mk_http_request_end(socket) < 0) {
            mk_request_free_list(cs);
            return -1;
        }
        else {
            return 0;
        }
    }
    else if (ret > 0) {
        return 0;
    }

    /* avoid to make gcc cry :_( */
    return -1;
}

int mk_conn_error(int socket)
{
    int ret = -1;
    struct client_session *cs;
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("Connection Handler, error on FD %i", socket);
#endif

    /* Plugin hook */
    ret = mk_plugin_event_error(socket);
    switch(ret) {
    case MK_PLUGIN_RET_EVENT_OWNED:
        return MK_PLUGIN_RET_CONTINUE;
    case MK_PLUGIN_RET_EVENT_CLOSE:
        return -1;
    case MK_PLUGIN_RET_EVENT_CONTINUE:
        break; /* just return controller to invoker */
    }

    sched = mk_sched_get_thread_conf();
    mk_sched_remove_client(sched, socket);
    cs = mk_session_get(socket);
    if (cs) {
        mk_session_remove(socket);
    }

    return 0;
}

int mk_conn_close(int socket)
{
    int ret = -1;
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("[FD %i] Connection Handler, closed", socket);
#endif

    /* Plugin hook */
    ret = mk_plugin_event_close(socket);
    switch(ret) {
    case MK_PLUGIN_RET_EVENT_OWNED:
        return MK_PLUGIN_RET_CONTINUE;
    case MK_PLUGIN_RET_EVENT_CLOSE:
        return -1;
    case MK_PLUGIN_RET_EVENT_CONTINUE:
        break; /* just return controller to invoker */
    }

    sched = mk_sched_get_thread_conf();
    mk_sched_remove_client(sched, socket);
    return 0;
}

int mk_conn_timeout(int socket)
{
    int ret = -1;
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("[FD %i] Connection Handler, timeout", socket);
#endif

    /* Plugin hook */
    ret = mk_plugin_event_timeout(socket);
    switch(ret) {
    case MK_PLUGIN_RET_EVENT_OWNED:
        return MK_PLUGIN_RET_CONTINUE;
    case MK_PLUGIN_RET_EVENT_CLOSE:
        return -1;
    case MK_PLUGIN_RET_EVENT_CONTINUE:
        break; /* just return controller to invoker */
    }

    sched = mk_sched_get_thread_conf();
    mk_sched_check_timeouts(sched);

    return 0;
}
