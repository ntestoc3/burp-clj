(ns burp-clj.proxy
  (:require [burp-clj.helper :as helper])
  (:import [burp IProxyListener]))

(defn make-proxy-proc [proc-fn]
  (reify IProxyListener
    (processProxyMessage [this is-req msg]
      (proc-fn is-req msg))))

