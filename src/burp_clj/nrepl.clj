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

(extender/defsetting :nrepl-server/port 2233 validate/valid-port?)
(extender/defsetting :nrepl/nrepl-version "0.7.0")
(extender/defsetting :nrepl/refactor-version "2.5.0")
(extender/defsetting :nrepl/cider-version "0.25.0-alpha1")

(defn load-deps
  []
  (utils/add-dep [['nrepl (get-nrepl-version)]
                  ['refactor-nrepl (get-refactor-version)]
                  ['cider/cider-nrepl (get-cider-version)]]))

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

(defn start-nrepl
  []
  (when-not (started?)
    (helper/with-exception-default
      nil
      (load-deps)
      (let [port (get-port)
            _ (helper/log "nrepl starting at:" port )
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

