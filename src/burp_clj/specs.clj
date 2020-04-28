(ns burp-clj.specs
  (:require [clojure.spec.alpha :as s]
            [me.raynes.fs :as fs]
            [burp-clj.validate :as validate]
            )
  )

(s/def :script-source/git validate/valid-git-source?)
(s/def :script-source/file fs/exists?)
(s/def ::script-source (s/or :git
                             :script-source/git
                             :file
                             :script-source/file))


(s/def :tab/captain string?)
(s/def :tab/view validate/valid-swing-comp?)

(s/def ::tab (s/keys :req-un [:tab/captain :tab/view]))

(s/def :burp/content-menu validate/valid-context-menu-factory?)
(s/def :burp/extension-state-listener validate/valid-extension-state-listener?)
(s/def :burp/http-listener validate/valid-http-listener?)
(s/def :burp/intruder-payload-generator validate/valid-intruder-payload-generator-factory?)
(s/def :burp/intruder-payload-processor validate/valid-intruder-payload-processor?)
(s/def :burp/message-editor-tab validate/valid-message-editor-tab-factory?)
(s/def :burp/proxy-listener validate/valid-proxy-listener?)
(s/def :burp/scanner-check validate/valid-scanner-check?)
(s/def :burp/scanner-insertion-point-provider validate/valid-scanner-insertion-point-provider?)
(s/def :burp/scanner-listener validate/valid-scanner-listener?)
(s/def :burp/scope-change-listener validate/valid-scope-change-listener?)
(s/def :burp/session-handling-action validate/valid-session-handling-action?)
(s/def :burp/tab validate/valid-tab?)

(s/def :script/name string?)
(s/def :script/version string?)
(s/def :script/min-burp-clj-version string?)
(s/def :script/enable-callback fn?)
(s/def :script/disable-callback fn?)

