(ns burp.proxy
  (:require [burp.utils :as utils])
  (:import [burp IProxyListener]))

(defn make-proxy-proc [proc-fn]
  (reify IProxyListener
    (processProxyMessage [this is-req msg]
      (when-not is-req
        (let [req-resp (.getMessageInfo msg)
              req (utils/analyze-request req-resp)
              resp (-> (.getResponse req-resp)
                       utils/analyze-response)]
          (utils/log "request info:" req
                     "\n"
                     "response info:" resp)
          (proc-fn {:request req
                    :response resp
                    :message req-resp}))))))

