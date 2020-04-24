(ns burp.core
  (:require [nrepl.server :refer [start-server stop-server]]
            [cemerick.pomegranate :refer [add-dependencies]])
  (:import [burp
            IBurpExtender
            IBurpExtenderCallbacks
            IProxyListener
            IInterceptedProxyMessage
            IHttpRequestResponse
            IExtensionStateListener
            ]
           [java.io PrintWriter]))

;;;;;;;;;;;;;;;;;;;;; extension reg
(def state (atom nil))

(defn log [s]
  (.printOutput (:extender @state) s))

(defn nrepl-handler []
  (require 'cider.nrepl)
  (ns-resolve 'cider.nrepl 'cider-nrepl-handler))

(defn extension-unload []
  (reify IExtensionStateListener
    (extensionUnloaded [_]
      (log "stopping nrepl server.")
      (stop-server (:nrepl-server @state))
      (log "extension unload."))))

(defn register
  "注册回调"
  [cbs]
  (.setExtensionName cbs "clojure nrepl")
  (let [stdout (-> (.getStdout cbs)
                   (PrintWriter. true))
        repl-port 22233
        nrepl-server (start-server :bind "0.0.0.0"
                                   :port repl-port
                                   :handler (nrepl-handler))]
    (swap! state assoc
           :extender cbs
           :nrepl-server nrepl-server)
    (.registerExtensionStateListener cbs (extension-unload))
    (.println stdout (str "nrepl started at" repl-port))))

;;;;;;;;;;;;;;;;;;;;;;;;;;; helpers
(defn proxy-proc []
  (reify IProxyListener
    (processProxyMessage [this is-req  msg]
      (let [req-resp (.getMessageInfo msg)]
        (log (str "req:" is-req
                  " req length:" (count (.getRequest req-resp))
                  " resp length:" (count (.getResponse req-resp))))))
    ))

;; (def helper (.getHelpers (:extender @state)))
;; (.registerProxyListener  (:extender @state) (proxy-proc))

(def default-repo (merge cemerick.pomegranate.aether/maven-central
                         {"clojars" "https://clojars.org/repo"}))
(defn add-dep
  [libs & {:keys [repos]
           :or {repos default-repo}}]
  (add-dependencies :coordinates libs :repositories repos))


(require '[clojure.reflect :as reflect])
(require '[clojure.pprint :as pp])

(defn get-classinfo
  [class]
  (->> (reflect/reflect class)
       :members
       (sort-by :name)))

(defn print-classinfo
  [class]
  (->> (get-classinfo class)
       (pp/print-table [:name :flags :parameter-types :return-type])))


