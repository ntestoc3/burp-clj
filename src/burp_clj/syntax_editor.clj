(ns burp-clj.syntax-editor
  (:require [burp-clj.utils :as utils]
            [seesaw.rsyntax :as rsyntax]
            [seesaw.complete :as ac]
            [seesaw.core :as gui]
            [seesaw.font :as font]
            [seesaw.keymap :as keymap]))

(defn syntax-text-area
  [input-map & opts]
  (rsyntax/with-rsyntax-input-action-map-context
    (let [ta (apply rsyntax/text-area opts)]
      (when input-map
        (doseq [[ik ak] input-map]
          (keymap/map-key ta ik ak :scope :self)))
      ta)))


(comment
  (defn print-all-keys [ta]
    (let [im (.getInputMap ta)]
      (doseq [k (.allKeys im)]
        (println "key:" (str k) " action:"(.get im k)))))

  (def txt (syntax-text-area {"control P" "caret-up"
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

  (def cp {:ac-words ["request" "response"]
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

  (def ac (ac/completion cp
                         :parameter-assistance? true
                         :trigger-key "control PERIOD"
                         :auto-activation? true
                         ;; :show-desc-window? true
                         :target txt
                         :delay 200))

  (utils/show-ui (rsyntax/text-scroll txt :line-numbers? true))

  (print-all-keys txt)

  )


