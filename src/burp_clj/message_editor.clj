(ns burp-clj.message-editor
  (:require [burp-clj.helper :as helper]
            [burp-clj.syntax-editor :refer [syntax-text-area]]
            [seesaw.rsyntax :as rsyntax]
            [seesaw.core :as gui]
            [burp-clj.utils :as utils]
            [taoensso.timbre :as log])
  (:import [burp
            IMessageEditorTab
            IMessageEditorTabFactory]))

(defn make-syntax-editor-tab
  "使用syntax-text-area构造IMessageEditorTab

  - `:title` tab标题
  - `:proc-msg-fn` 处理消息的函数，参数为[^bytes content, ^boolean isRequest],返回要显示的消息字符串
     如果返回为nil，则tab不显示
  - `:modify-msg-fn` 修改消息函数，如果不提供此函数，则editor中的编辑不起任何作用

       如果:editable?为true,则editor内容有修改时调用此函数，

       参数为[^bytes message, ^boolean isRequest, ^String doc]:

       message为原始消息，isRequest是否为request, doc为editor中的内容，

       返回修改后的message, 必须是完整的http message.
  - `:editable?` 是否可编辑
  - `:key-maps` syntax-text-area的按键映射，可选
  - `:auto-completion` syntax-text-area的自动补全，可选
  - `:syntax-text-area-opts` 传给syntax-text-area的其它参数,参考`seesaw.rsyntax/text-area-options`
  "
  [{:keys [title
           proc-msg-fn
           modify-msg-fn
           editable?
           key-maps
           auto-completion
           syntax-text-area-opts]
    :or {title "message editor"}}]
  (let [state (atom {})
        ta (apply syntax-text-area {:key-maps key-maps :auto-completion auto-completion}
                  :editable? editable?
                  (apply concat syntax-text-area-opts))
        comp (rsyntax/text-scroll ta
                                  :line-numbers? true
                                  :fold-indicator? true
                                  :icon-row-header? true)
        check-modify (fn []
                       (when (and editable?
                                  modify-msg-fn
                                  (not= (gui/text ta)
                                        (get @state :view-data)))
                         (when-let [new-msg (modify-msg-fn
                                             (get @state :message)
                                             (get @state :is-req)
                                             (gui/text ta))]
                           (let [new-data (proc-msg-fn new-msg (get @state :is-req))]
                             (gui/text! ta new-data)
                             (swap! state assoc
                                    :message new-msg
                                    :view-data new-data
                                    :modify true))))) ]
    (when editable?
      (gui/listen ta :focus-lost (fn [_] (check-modify))))
    (reify IMessageEditorTab
      (^bytes getMessage [this]
       ;; 从此tab切换走时就会调用
       (check-modify)
       (-> (or (get @state :message) "")
           (utils/->bytes)))
      (^bytes getSelectedData [this]
       (-> (or (gui/selection ta) "")
           (utils/->bytes)))
      (getTabCaption [this] title)
      (getUiComponent [this] comp)
      (^boolean isEnabled [this ^bytes content ^boolean is-req]
       ;; 决定是否需要显示控件时调用
       (boolean (proc-msg-fn content is-req)))
      (^boolean isModified [this]
       ;; 如果editable?为true,从此tab切换走时就会调用，确定是否替换message
       ;; 如果返回true,则使用get-message替换message
       (let [modifyed (and editable?
                           (get @state :modify))]
         modifyed))
      (^void setMessage [this ^bytes content ^boolean is-req]
       ;; 每次切换到此tab就调用一次
       (when-let [data (proc-msg-fn content is-req)]
         (swap! state assoc
                :message content
                :is-req is-req
                :view-data data
                :modify false)
         (gui/text! ta data))))))

(defn make-message-editor-tab
  "创建一个message-editor-tab

  - `make-fn` 参数为[message-editor-controller editable] 返回IMessageEditorTab"
  [make-fn]
  (reify IMessageEditorTabFactory
    (createNewInstance [this controller editable]
      (make-fn controller editable))))

