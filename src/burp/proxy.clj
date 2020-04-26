(ns burp.proxy
  (:require [burp.helper :as helper])
  (:import [burp IProxyListener]))

(defn make-proxy-proc [proc-fn]
  (reify IProxyListener
    (processProxyMessage [this is-req msg]
      (proc-fn is-req msg))))

(comment
  (when-not is-req
    (let [req-resp (.getMessageInfo msg)
          req (helper/analyze-request req-resp)
          resp (-> (.getResponse req-resp)
                   helper/analyze-response)]
      (helper/log "request info:" req
                  "\n"
                  "response info:" resp)
      (proc-fn {:request req
                :response resp
                :message req-resp})))

  )
