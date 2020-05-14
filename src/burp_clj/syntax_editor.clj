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
           javax.swing.KeyStroke
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

(defn my-completion-provider
  [init-words]
  (proxy [DefaultCompletionProvider] [init-words]
    (isValidChar [ch]
      (-> (or (Character/isLetterOrDigit ch)
              (#{\. \_ \' \/ \- \:} ch))
          boolean))))

(defn make-completion
  "`init-words` 初始补全的单词列表"
  [{:keys [auto-activate
           activate-delay
           activate-rules
           show-desc
           use-parameter-assistance
           init-words
           trigger-key
           completions
           auto-complete-single
           ]
    :or {auto-activate true
         auto-complete-single false
         init-words []
         activate-rules "abcdefghijklmnopqrstuvwxyz.:/-"
         activate-delay 200
         }}]
  (let [init-words (into-array String init-words)
        provider (my-completion-provider init-words)
        ac (AutoCompletion. provider)]
    (when auto-activate
      (.setAutoActivationEnabled ac true)
      (.setAutoActivationDelay ac activate-delay)
      (.setAutoActivationRules provider true activate-rules))
    (when show-desc
      (.setShowDescWindow ac true))
    (when use-parameter-assistance
      (.setParameterAssistanceEnabled ac true))
    (when trigger-key
      (.setTriggerKey ac (KeyStroke/getKeyStroke trigger-key)))
    (.setAutoCompleteSingleChoices ac auto-complete-single)

    (doseq [[comp-type comps] completions]
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

(defn syntax-text-area
  [{:keys [auto-completion
           auto-indent
           anti-aliasing
           input-map
           action-map
           code-folding]
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
        (when auto-indent
          (.setAutoIndentEnabled ta true))
        (when anti-aliasing
          (.setAntiAliasingEnabled ta true))
        (when code-folding
          (.setCodeFoldingEnabled ta true))
        (when action-map
          (let [am (.getActionMap ta)]
            (doseq [[ak action] action-map]
              (.put am ak action))))
        (when input-map
          (let [im (.getInputMap ta)]
            (doseq [[ik ak] input-map]
              (.put im (KeyStroke/getKeyStroke ik) ak))))
        (when auto-completion
          (-> (make-completion auto-completion)
              (.install ta)))
        ta)
      (finally
        (javax.swing.text.JTextComponent/addKeymap rtextarea-keymap old-keymap)
        (UIManager/put rsyntax-textarea-action-map old-syntax-action)
        (UIManager/put rsyntax-textarea-input-map old-syntax-input)
        (UIManager/put rtextarea-action-map old-action)
        (UIManager/put rtextarea-input-map old-input)))))


(enable-templates!)

(comment

  (def am {:use-parameter-assistance true
           :trigger-key "control PERIOD"
           :activate-delay 10
           :init-words ["request" "response"]
           :completions {:basic [{:text "test"}
                                 {:text "tencent"
                                  :desc "tencent test"
                                  :summary "test text"}]
                         :template [{:text "defun"
                                     :def-text "(defn fn-name [arg] ...)"
                                     :template "(defn ${fname} [${arg}]
  (+ ${arg} 1)
  ${cursor})"
                                     :desc "def function"
                                     :summary "define function template"
                                     }]}})


  (def txt (syntax-text-area {:auto-completion am
                              :input-map {"control P" "caret-up"
                                          "control N" "caret-down"
                                          "control B" "caret-backward"
                                          "control F" "caret-forward"
                                          "control A" "caret-begine-line"
                                          "control E" "caret-end-line"
                                          "control D" "delete-next"
                                          "alt B" "caret-previous-word"
                                          "alt F" "caret-next-word"
                                          }
                              }
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

  (.allKeys am)

  (.get im (javax.swing.KeyStroke/getKeyStroke "LEFT"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "RIGHT"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "HOME"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "END"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "control LEFT"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "control RIGHT"))

  (.get im (javax.swing.KeyStroke/getKeyStroke "UP"))

  )


