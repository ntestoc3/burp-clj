(ns burp-clj.nrepl
  (:require [burp-clj.extender :as extender]
            [burp-clj.extension-state :refer [make-unload-callback]]
            [burp-clj.state :as state]
            [burp-clj.utils :as utils]
            [burp-clj.validate :as validate]
            [burp-clj.helper :as helper]))

(defmacro dyn-call
  [ns-sym]
  (let [ns (-> (namespace ns-sym)
               symbol)
        sym (-> (name ns-sym)
                symbol)]
    `(do
       (require '~ns)
       (ns-resolve '~ns '~sym))))

(defn get-server-port
  []
  (or (extender/get-setting :nrepl-server/port)
      2233))

(defn set-server-port!
  [port]
  {:pre [(validate/valid-port? port)]}
  (extender/set-setting! :nrepl-server/port port))

(defn started?
  []
  (-> (:nrepl-server @state/state)
      boolean))

(defn stop-nrepl
  []
  (when-let [server (:nrepl-server @state/state)]
    (extender/remove-extension-state-listener! :nrepl-server)
    ((dyn-call nrepl.server/stop-server) server)
    (swap! state/state dissoc :nrepl-server)
    (helper/log "nrepl stopped!")))

(defn load-deps
  []
  (utils/add-dep '[[nrepl "0.7.0"]
                   [refactor-nrepl "2.5.0"]
                   [cider/cider-nrepl "0.25.0-alpha1"]]))

(defn start-nrepl
  []
  (when-not (started?)
    (helper/with-exception-default
      nil
      (load-deps)
      (let [port (get-server-port)
            _ (helper/log (-> (Thread/currentThread)
                              (.getName))
                          "nrepl starting at:" port )
            cider-nrepl-handler (dyn-call cider.nrepl/cider-nrepl-handler)
            wrap-refactor (dyn-call refactor-nrepl.middleware/wrap-refactor)
            start-server (dyn-call nrepl.server/start-server)
            nrepl-server (start-server
                          :bind "0.0.0.0"
                          :port port
                          :handler (-> cider-nrepl-handler
                                       wrap-refactor))]
        (swap! state/state assoc :nrepl-server nrepl-server)
        (extender/register-extension-state-listener!
         :nrepl-server
         (make-unload-callback stop-nrepl))
        (helper/log "nrepl started.")))))

