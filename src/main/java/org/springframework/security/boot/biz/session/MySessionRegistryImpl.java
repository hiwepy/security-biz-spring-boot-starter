/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.biz.session;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import org.springframework.context.ApplicationListener;
import org.springframework.data.redis.core.BoundHashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings("unchecked")
public class MySessionRegistryImpl implements SessionRegistry, ApplicationListener<SessionDestroyedEvent> {

    private static final String SESSIONIDS = "sessionIds";
    private static final String PRINCIPALS = "principals";

    private RedisTemplate redisTemplate;

//    private final ConcurrentMap<Object, Set<String>> principals = new ConcurrentHashMap();
//    private final Map<String, SessionInformation> sessionIds = new ConcurrentHashMap();

    public MySessionRegistryImpl() {
    }

    public List<Object> getAllPrincipals() {
        return new ArrayList<>(this.getPrincipalsKeySet());
    }

    public List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {
        Set<String> sessionsUsedByPrincipal =  this.getPrincipals(((UserDetails)principal).getUsername());
        if (sessionsUsedByPrincipal == null) {
            return Collections.emptyList();
        } else {
            List<SessionInformation> list = new ArrayList<>(sessionsUsedByPrincipal.size());
            Iterator<String> var5 = sessionsUsedByPrincipal.iterator();
            while (true) {
                SessionInformation sessionInformation;
                do {
                    do {
                        if (!var5.hasNext()) {
                            return list;
                        }
                        String sessionId = (String) var5.next();
                        sessionInformation = this.getSessionInformation(sessionId);
                    } while (sessionInformation == null);
                } while (!includeExpiredSessions && sessionInformation.isExpired());
                list.add(sessionInformation);
            }
        }
    }

    public SessionInformation getSessionInformation(String sessionId) {
        Assert.hasText(sessionId, "SessionId required as per interface contract");
        return (SessionInformation) this.getSessionInfo(sessionId);
    }

    public void onApplicationEvent(SessionDestroyedEvent event) {
        String sessionId = event.getId();
        this.removeSessionInformation(sessionId);
    }

    public void refreshLastRequest(String sessionId) {
        Assert.hasText(sessionId, "SessionId required as per interface contract");
        SessionInformation info = this.getSessionInformation(sessionId);
        if (info != null) {
            info.refreshLastRequest();
        }

    }

    public void registerNewSession(String sessionId, Object principal) {
        Assert.hasText(sessionId, "SessionId required as per interface contract");
        Assert.notNull(principal, "Principal required as per interface contract");
        if (log.isDebugEnabled()) {
            log.debug("Registering session " + sessionId + ", for principal " + principal);
        }

        if (this.getSessionInformation(sessionId) != null) {
            this.removeSessionInformation(sessionId);
        }

        this.addSessionInfo(sessionId, new SessionInformation(principal, sessionId, new Date()));

//        this.sessionIds.put(sessionId, new SessionInformation(principal, sessionId, new Date()));
        Set<String> sessionsUsedByPrincipal = (Set) this.getPrincipals(principal.toString());
        if (sessionsUsedByPrincipal == null) {
            sessionsUsedByPrincipal = new CopyOnWriteArraySet<>();
            Set<String> prevSessionsUsedByPrincipal = (Set) this.putIfAbsentPrincipals(principal.toString(), sessionsUsedByPrincipal);
            if (prevSessionsUsedByPrincipal != null) {
                sessionsUsedByPrincipal = prevSessionsUsedByPrincipal;
            }
        }

        ((Set) sessionsUsedByPrincipal).add(sessionId);
        this.putPrincipals(principal.toString(), sessionsUsedByPrincipal);
        if (log.isTraceEnabled()) {
            log.trace("Sessions used by '" + principal + "' : " + sessionsUsedByPrincipal);
        }

    }

    public void removeSessionInformation(String sessionId) {
        Assert.hasText(sessionId, "SessionId required as per interface contract");
        SessionInformation info = this.getSessionInformation(sessionId);
        if (info != null) {
            if (log.isTraceEnabled()) {
                log.debug("Removing session " + sessionId + " from set of registered sessions");
            }

            this.removeSessionInfo(sessionId);
            Set<String> sessionsUsedByPrincipal = (Set) this.getPrincipals(info.getPrincipal().toString());
            if (sessionsUsedByPrincipal != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Removing session " + sessionId + " from principal's set of registered sessions");
                }

                sessionsUsedByPrincipal.remove(sessionId);
                if (sessionsUsedByPrincipal.isEmpty()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Removing principal " + info.getPrincipal() + " from registry");
                    }

                    this.removePrincipal(((UserDetails)info.getPrincipal()).getUsername());
                }

                if (log.isTraceEnabled()) {
                    log.trace("Sessions used by '" + info.getPrincipal() + "' : " + sessionsUsedByPrincipal);
                }

            }
        }
    }


    public void addSessionInfo(final String sessionId, final SessionInformation sessionInformation) {
        BoundHashOperations<String, String, SessionInformation> hashOperations = redisTemplate.boundHashOps(SESSIONIDS);
        hashOperations.put(sessionId, sessionInformation);
    }

    public SessionInformation getSessionInfo(final String sessionId) {
        BoundHashOperations<String, String, SessionInformation> hashOperations = redisTemplate.boundHashOps(SESSIONIDS);
        return hashOperations.get(sessionId);
    }

    public void removeSessionInfo(final String sessionId) {
        BoundHashOperations<String, String, SessionInformation> hashOperations = redisTemplate.boundHashOps(SESSIONIDS);
        hashOperations.delete(sessionId);
    }

    public Set<String> putIfAbsentPrincipals(final String key, final Set<String> set) {
        BoundHashOperations<String, String, Set<String>> hashOperations = redisTemplate.boundHashOps(PRINCIPALS);
        hashOperations.putIfAbsent(key, set);
        return hashOperations.get(key);
    }

   
	public void putPrincipals(final String key, final Set<String> set) {
        BoundHashOperations<String, String, Set<String>> hashOperations = redisTemplate.boundHashOps(PRINCIPALS);
        hashOperations.put(key,set);
    }

    public Set<String> getPrincipals(final String key) {
        BoundHashOperations<String, String, Set<String>> hashOperations = redisTemplate.boundHashOps(PRINCIPALS);
        return hashOperations.get(key);
    }

    public Set<String> getPrincipalsKeySet() {
        BoundHashOperations<String, String, Set<String>> hashOperations = redisTemplate.boundHashOps(PRINCIPALS);
        return hashOperations.keys();
    }

    public void removePrincipal(final String key) {
        BoundHashOperations<String, String, Set<String>> hashOperations = redisTemplate.boundHashOps(PRINCIPALS);
        hashOperations.delete(key);
    }


}