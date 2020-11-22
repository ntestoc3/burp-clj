(ns burp-clj.syntax-editor
  (:require [burp-clj.utils :as utils]
            [seesaw.rsyntax :as rsyntax]
            [seesaw.complete :as ac]
            [seesaw.core :as gui]
            [seesaw.font :as font]
            [seesaw.keymap :as keymap]))

(defn syntax-text-area
  [{:keys [key-maps auto-completion]} & opts]
  (let [ta (rsyntax/with-rsyntax-input-action-map-context
             (apply rsyntax/text-area opts))]
    (when auto-completion
      (apply ac/completion
             (:provider auto-completion)
             (apply concat
                    [:target ta]
                    (dissoc auto-completion :provider))))
    (when key-maps
      (doseq [[ik ak] key-maps]
        (keymap/map-key ta ik ak :scope :self)))
    ta))


(comment
  (defn print-all-keys [ta]
    (let [im (.getInputMap ta)]
      (doseq [k (.allKeys im)]
        (println "key:" (str k) " action:" (.get im k)))))

  (def ac {:provider {:ac-words ["request" "response"]
                      :activate-rules "."
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
                                                }]}}
           :parameter-assistance? true
           :trigger-key "control PERIOD"
           :auto-activation? true
           ;; :show-desc-window? true
           :delay 200})

  (def txt (syntax-text-area {:key-maps {"control P" "caret-up"
                                         "control N" "caret-down"
                                         "control B" "caret-backward"
                                         "control F" "caret-forward"
                                         "control E" "caret-end-line"
                                         "control D" "delete-next"
                                         "control A" "caret-begin-line"
                                         "control S" "select-all"
                                         "alt B" "caret-previous-word"
                                         "alt F" "caret-next-word"
                                         }
                              :auto-completion ac}
                             :highlight-current-line? false
                             :syntax :python
                             :editable? true
                             :tab-size 1
                             :theme :vs
                             :wrap-lines? true
                             :code-folding? true
                             :anti-aliasing? true
                             :auto-indent? true
                             :font (font/font :font :monospaced
                                              :size 16)))

  (utils/show-ui (rsyntax/text-scroll txt :line-numbers? true))

  (print-all-keys txt)

  )


