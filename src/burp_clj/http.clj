(ns burp-clj.http
  (:require [burp-clj.helper :as helper])
  (:import [burp IHttpListener])
  )

(defn make-http-proc
  "`proc-fn` 接受一个参数的回调函数，{:tool 请求来源的标志
                                 :is-request 是否为request?
                                 :msg IHttpRequestResponse消息}"
  [proc-fn]
  (reify IHttpListener
    (processHttpMessage [this tool-flag is-req msg]
      (proc-fn {:tool (helper/tool-type-inv tool-flag)
                :is-request is-req
                :msg msg}))))
