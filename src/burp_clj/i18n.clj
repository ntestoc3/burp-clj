(ns burp-clj.i18n
  (:require [taoensso.tempura :as tempura :refer [tr]]
            [burp-clj.extender :as extender]
            [taoensso.timbre :as log]))


(extender/defsetting :language (or (keyword (System/getProperty "user.language"))
                                   :en))

(def supported-lang {:en "english"
                     :zh "中文简体"})
(def translations
  {;; English language resources
   :en {:missing       "**MISSING**" ; Fallback for missing resources
        :plugin-name "Clojure Plugin"
        :choose-folder "Choose Folder"

        :add-source-dlg {:title "add source info"
                         :msg "input source target(support local folder or git):"
                         :not-valid "%1 not a valid source!"}

        :script-source-form {:header "Scripts Source"
                             :add "Add"
                             :remove "Remove"
                             :reload "Reload Scripts!"
                             }

        :http-proxy-form {:header "HTTP Proxy"
                          :check-text "Use HTTP proxy"
                          :host "HTTP proxy host:"
                          :port "HTTP proxy port:"
                          :not-valid-port "not valid port: %1"
                          :username "Username:"
                          :password "Password:"
                          :exclusion "Exclusion:"
                          :exclusion-tip "The list of hosts to exclude from proxying."
                          }

        :setting-form {:header "Setting"
                       :select-language "Select Language:"
                       :select-language-tip "The selected language will not take effect until the plugin is reloaded."
                       :misc-tab-title "Misc"
                       }

        :script-list-form {:header "Scripts List"
                           :col-enable "enable"
                           :col-name "name"
                           :col-version "version"
                           :menu-reload "reload script"

                           }

        :collaborator {:http-summary "The Collaborator server received an %1 request."
                       :dns-summary "The Collaborator server received a DNS lookup of type %1 for the domain name %2 ."
                       :col-time "Time"
                       :col-ip "IP"
                       :col-type "Type"
                       :col-payload "Payload"
                       :col-comment "Comment"
                       :unsupport-msg-tip "unsupported."
                       :poll-time-left "Poll every"
                       :poll-time-right "seconds."
                       :btn-poll-now "Poll now"
                       :btn-gen-payload "Generate payload"
                       }

        :message-viewer {:lbl-filter "Filter:"
                         :filter-clear-all "clear all..."
                         }

        }

   ;; Chinese language resources
   :zh {:missing "**缺失项**"
        :plugin-name "Clojure插件"
        :choose-folder "选择文件夹"

        :add-source-dlg {:title "添加源"
                         :msg "输入要添加的源(支持本地目录和git):"
                         :not-valid "%1 不是有效的源!"}

        :script-source-form {:header "脚本源"
                             :add "添加"
                             :remove "删除"
                             :reload "重新加载脚本"
                             }

        :http-proxy-form {:header "HTTP代理"
                          :check-text "使用HTTP代理"
                          :host "HTTP代理主机:"
                          :port "HTTP代理端口:"
                          :not-valid-port "不是有效端口: %1"
                          :username "用户名:"
                          :password "密码:"
                          :exclusion "排除列表:"
                          :exclusion-tip "使用|间隔，此列表中的主机请求不经过代理."
                          }

        :setting-form {:header "设置"
                       :select-language "选择语言:"
                       :select-language-tip "重新加载插件后所选的语言才会生效。"
                       :misc-tab-title "其它"
                       }

        :script-list-form {:header "脚本列表"
                           :col-enable "启用"
                           :col-name "名称"
                           :col-version "版本"
                           :menu-reload "重新加载脚本"
                           }

        :collaborator {:http-summary "反连服务器收到 %1 请求。"
                       :dns-summary "反连服务器收到类型为%1的DNS请求，目标为 %2."
                       :col-time "时间"
                       :col-ip "IP"
                       :col-type "类型"
                       :col-payload "Payload"
                       :col-comment "注释"
                       :unsupport-msg-tip "未支持."
                       :poll-time-left "每"
                       :poll-time-right "秒拉取1次."
                       :btn-poll-now "现在拉取"
                       :btn-gen-payload "生成Payload"
                       }

        :message-viewer {:lbl-filter "过滤器:"
                         :filter-clear-all "清除全部..."
                         }
        }})

(defn app-tr
  "Get a localized resource by language setting.

  `trans-dict` translation dict.

  `resource` Resource keyword.

  `params`   Optional positional parameters.

  return translation of `resource` in current language setting or a placeholder."
  [trans-dict resource & params]
  (tr {:dict trans-dict}
      [(get-language) :en]
      [resource]
      (vec params)))

;; burp-clj plugin tr
(def ptr (partial app-tr translations))
