(ns burp-clj.ui
  (:require [seesaw.core :as gui]
            [seesaw.bind :as bind]
            [seesaw.border :as border]
            [burp-clj.state :as state]
            [seesaw.mig :refer [mig-panel]]
            [burp-clj.extender :as extender]
            [burp-clj.helper :as helper]
            [burp-clj.nrepl :as nrepl]))

(defn make-nrepl-view
  []
  (let [nrepl-port (gui/text :text (str (nrepl/get-port)))
        get-nrepl-btn-txt (fn [started]
                            (if started
                              "stop nREPL"
                              "start nREPL"))
        nrepl-start-stop-btn (gui/button
                              :text (-> (nrepl/started?)
                                        get-nrepl-btn-txt)
                              :id :nrepl-start-stop)
        check-set-nrepl-port (fn []
                               (let [port (gui/text nrepl-port)]
                                 (try
                                   (->> port
                                        Integer/parseInt
                                        nrepl/set-port!)
                                   true
                                   (catch Exception e
                                     (gui/alert e
                                                (str "not valid port: " port)
                                                :type :error)
                                     (gui/invoke-later
                                      (gui/text! nrepl-port (str (nrepl/get-port))))
                                     false))))]
    (bind/bind
     state/state
     (bind/transform #(-> (:nrepl-server %)
                          get-nrepl-btn-txt))
     (bind/property nrepl-start-stop-btn :text))
    (gui/listen nrepl-start-stop-btn
                :action (fn [e]
                          (when (check-set-nrepl-port)
                            (if (:nrepl-server @state/state)
                              (nrepl/stop-nrepl)
                              (nrepl/start-nrepl)))))

    (mig-panel
     :border (border/empty-border :left 10 :top 10)
     :items [
             [(gui/checkbox
               :text "start nrepl server on extension load"
               :selected? (extender/get-setting :nrepl/start-on-load)
               :listen [:selection
                        (fn [e]
                          (->> (gui/selection e)
                               (extender/set-setting! :nrepl/start-on-load)))])
              "span, grow, wrap"]

             ["nrepl version:"]
             [(gui/text :text (nrepl/get-nrepl-version)
                        :listen [:document
                                 #(-> (gui/text %)
                                      nrepl/set-nrepl-version!)])
              "wrap, grow"]

             ["cider-nrepl version:"]
             [(gui/text :text (nrepl/get-cider-version)
                        :listen [:document
                                 #(-> (gui/text %)
                                      nrepl/set-cider-version!)])
              "wrap, grow"]

             ["refactor-nrepl version:"]
             [(gui/text :text (nrepl/get-refactor-version)
                        :listen [:document
                                 #(-> (gui/text %)
                                      nrepl/set-refactor-version!)])
              "wrap, grow"]

             ["server port:"]
             [nrepl-port "wrap, grow, wmin 250,"]

             [nrepl-start-stop-btn "span, grow"]])))

(defn make-view
  []
  (gui/tabbed-panel :placement :top
                    :overflow :scroll
                    :tabs [{:title "nREPL"
                            :tip "setting nrepl server"
                            :content (make-nrepl-view)}
                           #_{:title "extension"
                              :tip "manager extensions"
                              :content nil}]))
