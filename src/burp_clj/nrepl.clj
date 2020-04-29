(ns burp-clj.nrepl
  (:require [burp-clj.extender :as extender]
            [burp-clj.extension-state :refer [make-unload-callback]]
            [burp-clj.state :as state]
            [burp-clj.utils :as utils]
            [burp-clj.validate :as validate]
            [burp-clj.helper :as helper]
            [taoensso.timbre :as log]))

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
    ;; 如果是在extension-state-listener中执行，则不能remove，会修改注册的list
    ;; 造成java.util.ConcurrentModificationException
    ;; (extender/remove-extension-state-listener! :nrepl-server)
    ((dyn-call nrepl.server/stop-server) server)
    (swap! state/state dissoc :nrepl-server)
    (log/info "nrepl stopped!")))

(defn wrap-classloader
  [h]
  (fn [msg]
    (utils/ensure-dynamic-classloader)
    (h msg)))

(defn start-nrepl
  []
  (when-not (started?)
    (helper/with-exception-default
      nil
      (load-deps)
      ;; (log/info :start-nrepl :refactor-nrepl-version
      ;;           ((dyn-call refactor-nrepl.core/version)))
      (let [port (get-port)
            _ (log/info "nrepl starting at:" port )
            cider-nrepl-handler (dyn-call cider.nrepl/cider-nrepl-handler)
            wrap-refactor (dyn-call refactor-nrepl.middleware/wrap-refactor)
            start-server (dyn-call nrepl.server/start-server)
            nrepl-server (start-server
                          :bind "0.0.0.0"
                          :port port
                          :handler (-> cider-nrepl-handler
                                       wrap-refactor
                                       wrap-classloader))]
        (swap! state/state assoc :nrepl-server nrepl-server)
        (extender/register-extension-state-listener!
         :nrepl-server
         (make-unload-callback stop-nrepl))
        (log/info "nrepl started.")))))

