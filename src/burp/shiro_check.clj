(ns burp.shiro-check
  (:require [burp.proxy :as proxy]
            [burp.helper :as helper]))

(defn shiro-check
  [is-req msg]
  (let [req-resp (.getMessageInfo msg)
        req (.getRequest req-resp)
        jsession-id (helper/get-request-parameter req "JSESSIONID")]
    (when jsession-id
      (if is-req
        (when (not (helper/get-request-parameter req "rememberMe"))
          (->> (helper/build-parameter "rememberMe" "test" :cookie)
               (helper/add-parameter req)
               (.setRequest req-resp)))
        (let [resp (-> (.getResponse req-resp)
                       helper/analyze-response)]
          (when (->> (:cookies resp)
                     (take-while #(and (= (:name %) "rememberMe")
                                       (= (:value %) "deleteMe")))
                     seq)
            (doto req-resp
              (.setHighlight "orange")
              (.setComment "maybe Shiro!"))))))))

(defn shiro-check-proxy []
  (proxy/make-proxy-proc shiro-check))
