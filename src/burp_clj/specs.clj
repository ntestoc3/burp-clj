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

(s/def :burp/context-menu validate/valid-context-menu-factory?)
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
(s/def :script/context-menu (s/every-kv keyword? :burp/context-menu))
(s/def :script/extension-state-listener (s/every-kv keyword? :burp/extension-state-listener))
(s/def :script/http-listener (s/every-kv keyword? :burp/http-listener))
(s/def :script/intruder-payload-generator (s/every-kv keyword? :burp/intruder-payload-generator))
(s/def :script/intruder-payload-processor (s/every-kv keyword? :burp/intruder-payload-processor))
(s/def :script/message-editor-tab (s/every-kv keyword? :burp/message-editor-tab))
(s/def :script/proxy-listener (s/every-kv keyword? :burp/proxy-listener))
(s/def :script/scanner-check (s/every-kv keyword? :burp/scanner-check))
(s/def :script/scanner-insertion-point-provider (s/every-kv keyword? :burp/scanner-insertion-point-provider))
(s/def :script/scanner-listener (s/every-kv keyword? :burp/scanner-listener))
(s/def :script/scope-change-listener (s/every-kv keyword? :burp/scope-change-listener))
(s/def :script/session-handling-action (s/every-kv keyword? :burp/session-handling-action))
(s/def :script/tab (s/every-kv keyword? ::tab))

(s/def ::script-info (s/keys :req-un [:script/name
                                      :script/version
                                      :script/min-burp-clj-version]
                             :opt-un [
                                      :script/enable-callback
                                      :script/disable-callback
                                      :script/context-menu
                                      :script/http-listener
                                      :script/intruder-payload-generator
                                      :script/intruder-payload-processor
                                      :script/message-editor-tab
                                      :script/proxy-listener
                                      :script/scanner-check
                                      :script/scanner-insertion-point-provider
                                      :script/scanner-listener
                                      :script/scope-change-listener
                                      :script/session-handling-action
                                      :script/tab]))
