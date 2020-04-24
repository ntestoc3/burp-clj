(ns burp.nrepl
  (:require [burp.extender :as extender]
            [burp.extension-state :refer [make-unload-callback]]
            [nrepl.server :refer [start-server stop-server]]
            [burp.utils :as utils]))

(defn nrepl-handler []
  (require 'cider.nrepl)
  (ns-resolve 'cider.nrepl 'cider-nrepl-handler))

(defn start-nrepl
  ([] (start-nrepl 2233))
  ([port]
   (let [nrepl-server (start-server :bind "0.0.0.0"
                                    :port port
                                    :handler (nrepl-handler))]
     (extender/register-extension-state-listener!
      :nrepl-server
      (make-unload-callback #(stop-server nrepl-server)))
     (utils/log "nrepl started at" port))))

