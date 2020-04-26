(ns burp-clj.nrepl
  (:require [burp-clj.extender :as extender]
            [burp-clj.extension-state :refer [make-unload-callback]]
            [nrepl.server :refer [start-server stop-server]]
            [burp-clj.state :as state]
            [refactor-nrepl.middleware :as refactor-nrepl]
            [com.billpiel.sayid.nrepl-middleware :as sayid-middleware]
            [burp-clj.validate :as validate]
            [burp-clj.helper :as helper]))

(defn nrepl-handler []
  (require 'cider.nrepl)
  (ns-resolve 'cider.nrepl 'cider-nrepl-handler))

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
    (stop-server server)
    (swap! state/state dissoc :nrepl-server)
    (helper/log "nrepl stopped!")))

(defn start-nrepl
  []
  (when-not (started?)
    (helper/with-exception-default
      nil
      (let [port (get-server-port)
            _ (helper/log "nrepl starting at:" port)
            nrepl-server (start-server :bind "0.0.0.0"
                                       :port port
                                       :handler (-> (nrepl-handler)
                                                    refactor-nrepl/wrap-refactor
                                                    #_sayid-middleware/wrap-sayid))]
        (swap! state/state assoc :nrepl-server nrepl-server)
        (extender/register-extension-state-listener!
         :nrepl-server
         (make-unload-callback stop-nrepl))
        (helper/log "nrepl started.")))))

