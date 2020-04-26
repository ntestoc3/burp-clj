(ns burp-clj.extension-state
  (:import [burp IExtensionStateListener]))


(defn make-unload-callback
  [callback-fn]
  (reify IExtensionStateListener
    (extensionUnloaded [_]
      (callback-fn))))
