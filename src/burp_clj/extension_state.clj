(ns burp-clj.extension-state
  (:require [burp-clj.helper :as helper])
  (:import [burp IExtensionStateListener]))


(defn make-unload-callback
  [callback-fn]
  (reify IExtensionStateListener
    (extensionUnloaded [_]
      (helper/with-exception-default
        nil
        (callback-fn)))))
