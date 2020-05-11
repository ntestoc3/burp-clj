(ns burp-clj.syntax-editor
  (:import [org.fife.ui.autocomplete
            DefaultCompletionProvider
            AutoCompletion
            CompletionProvider
            BasicCompletion
            AbstractCompletion
            FunctionCompletion
            MarkupTagCompletion
            ShorthandCompletion
            TemplateCompletion
            VariableCompletion]
           [org.fife.ui.rtextarea
            RTextAreaUI]
           [org.fife.ui.rtextarea
            RTextScrollPane]
           [org.fife.ui.rsyntaxtextarea
            RSyntaxTextArea
            RSyntaxTextAreaUI]
           javax.swing.UIManager)
  (:require [burp-clj.utils :as utils]
            [seesaw.rsyntax :as rsyntax]
            [taoensso.timbre :as log]
            [seesaw.core :as gui]
            [seesaw.font :as font]))

(def rtextarea-keymap
  (utils/class-private-field 'RTextAreaUI/RTEXTAREA_KEYMAP_NAME))

(def rtextarea-action-map
  (utils/class-private-field 'RTextAreaUI/SHARED_ACTION_MAP_NAME))

(def rtextarea-input-map
  (utils/class-private-field 'RTextAreaUI/SHARED_INPUT_MAP_NAME))

(def rsyntax-textarea-input-map
  (utils/class-private-field 'RSyntaxTextAreaUI/SHARED_INPUT_MAP_NAME))

(def rsyntax-textarea-action-map
  (utils/class-private-field 'RSyntaxTextAreaUI/SHARED_ACTION_MAP_NAME))

(defn remove-rtextarea-maps!
  []
  (javax.swing.text.JTextComponent/removeKeymap rtextarea-keymap)
  (UIManager/put rsyntax-textarea-action-map nil)
  (UIManager/put rsyntax-textarea-input-map nil)
  (UIManager/put rtextarea-action-map nil)
  (UIManager/put rtextarea-input-map nil))

(defn enable-templates!
  []
  (RSyntaxTextArea/setTemplatesEnabled true))

(defn syntax-text-area
  [{:keys [auto-completion
           auto-indent
           anti-aliasing
           code-folding
           use-templates]
    :or {auto-indent true
         code-folding true
         anti-aliasing true
         }} & opts]
  (let [old-keymap (javax.swing.text.JTextComponent/getKeymap rtextarea-keymap)
        old-syntax-action (UIManager/get rsyntax-textarea-action-map)
        old-syntax-input (UIManager/get rsyntax-textarea-input-map)
        old-action (UIManager/get rtextarea-action-map)
        old-input (UIManager/get rtextarea-input-map)]
    (remove-rtextarea-maps!)
    (try
      (let [ta (apply rsyntax/text-area opts)]
        (when auto-completion
          (.install auto-completion ta))
        (when auto-indent
          (.setAutoIndentEnabled ta true))
        (when anti-aliasing
          (.setAntiAliasingEnabled ta true))
        (when code-folding
          (.setCodeFoldingEnabled ta true))
        ta)
      #_(finally
        (javax.swing.text.JTextComponent/addKeymap rtextarea-keymap old-keymap)
        (UIManager/put rsyntax-textarea-action-map old-syntax-action)
        (UIManager/put rsyntax-textarea-input-map old-syntax-input)
        (UIManager/put rtextarea-action-map old-action)
        (UIManager/put rtextarea-input-map old-input)))))

(defn make-completion
  [words comps {:keys [auto-activate
                       activate-delay
                       show-desc
                       use-parameter-assistance
                       ]
                :or {auto-activate true
                     activate-delay 200
                     }}]
  (let [provider (DefaultCompletionProvider. (into-array String words))
        ac (AutoCompletion. provider)]
    (when auto-activate
      (.setAutoActivationEnabled ac true)
      (.setAutoActivationDelay ac activate-delay))
    (when show-desc
      (.setShowDescWindow ac true))
    (when use-parameter-assistance
      (.setParameterAssistanceEnabled ac true))

    (doseq [[comp-type comps] comps]
      (case comp-type
        :basic
        (doseq [{:keys [text desc summary]
                 :or {desc ""
                      summary ""}} comps]
          (->> (BasicCompletion. provider text desc summary)
               (.addCompletion provider)))

        :shorthand
        (doseq [{:keys [text replace desc summary]
                 :or {desc ""
                      summary ""}} comps]
          (->> (ShorthandCompletion. provider text replace desc summary)
               (.addCompletion provider)))

        :template
        (doseq [{:keys [text def-text template desc summary]
                 :or {desc ""
                      summary ""}} comps]
          (->> (TemplateCompletion. provider text def-text template desc summary)
               (.addCompletion provider)))

        :else
        (log/error :make-completion "unsupport completion type:" comp-type)))
    ac))


(def am (make-completion ["request" "response"]
                         {:basic [{:text "test"}
                                  {:text "tencent"
                                   :desc "tencent test"}]
                          :template [{:text "defun"
                                      :def-text "(defn fn-name [arg] ...)"
                                      :template "(defn ${fname} [${arg}]
  (+ ${arg} 1)
  ${cursor})"
                                      }]}
                         {:use-parameter-assistance true}))

(enable-templates!)

(comment
  (def txt (syntax-text-area {:auto-completion am
                              :use-templates true}
                             :syntax :clojure
                             :editable? true
                             :wrap-lines? true
                             :font (font/font :font :monospaced
                                              :size 16)
                             ))
  (utils/show-ui (RTextScrollPane. txt))


  (def im (.getInputMap txt))

  (def am (.getActionMap txt))


  (.allKeys im)

  (.get im (javax.swing.KeyStroke/getKeyStroke "LEFT"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "RIGHT"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "HOME"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "END"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "control LEFT"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "UP"))

  (.put im (javax.swing.KeyStroke/getKeyStroke "control P") "caret-up")

  (.put im (javax.swing.KeyStroke/getKeyStroke "control N") "caret-down")

  (.put im (javax.swing.KeyStroke/getKeyStroke "control B") "caret-backward")

  (.put im (javax.swing.KeyStroke/getKeyStroke "control F") "caret-forward")

  )


