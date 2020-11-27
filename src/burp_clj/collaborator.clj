(ns burp-clj.collaborator
  (:require [burp-clj.extender :as extender]
            [camel-snake-kebab.core :as csk]
            [burp-clj.helper :as helper]
            [burp-clj.utils :as utils]
            [seesaw.swingx :as guix]
            [seesaw.mig :refer [mig-panel]]
            [seesaw.table :as table]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [seesaw.core :as gui]))

(defn create
  []
  (extender/create-burp-collaborator-client))

(defn get-serever-loc
  "获取burp collaborator server的网络位置"
  [bc]
  (.getCollaboratorServerLocation bc))

(defn- gen-cmd
  [url params]
  (let [param-line (utils/encode-params params)]
    (if (empty? param-line)
      url
      (str url "?" param-line))))

(defn- get-cmd
  [url]
  (some-> (str/split url #"\?")
          second
          utils/decode-params))

(defn gen-payload
  "生成Burp Collaborator payloads
  `params`　生成带域名和params参数的payloads，如果不指定params，则只生成payload id"
  ([bc]
   (.generatePayload bc false))
  ([bc params]
   (-> (.generatePayload bc true)
       (gen-cmd params))))

(defn- bc-interaction->map
  [ia]
  (->> (.getProperties ia)
       (map (fn [[k v]]
              (let [new-k (csk/->kebab-case-keyword k)]
                [new-k
                 (if (#{:request :response :raw-query} new-k)
                   (-> (helper/base64-decode v)
                       utils/->string)
                   v)])))
       (into {})))

(defn get-collaborator-interactions
  "获取collaborator client的interactions

  返回的消息是未解码的原始interactions

  注意:
  如果客户端`bc`已经创建了ui,不建议自己调用此函数，可以通过ui的callback函数获取解码过的interaction
  "
  ([bc]
   (->> (.fetchAllCollaboratorInteractions bc)
        (map bc-interaction->map)))
  ([bc payload]
   (->> (.fetchCollaboratorInteractionsFor bc payload)
        (map bc-interaction->map))))

(defn get-infiltrator-interactions
  ([bc]
   (->> (.fetchAllInfiltratorInteractions bc)
        (map bc-interaction->map)))
  ([bc payload]
   (->> (.fetchInfiltratorInteractionsFor bc payload)
        (map bc-interaction->map))))

(defn- parse-collaborator-http
  "解析collaborator http消息"
  [{:keys [protocol request response type] :as msg}]
  (let [req-info (helper/flatten-format-req-resp request :request)]
    (merge
     (-> (get-cmd (:request/url req-info))
         (utils/map->nsmap :params))
     {:request/raw request
      :response/raw response
      :summary (str "The Collaborator server received an " protocol " request.")}
     (dissoc msg :request :response)
     req-info
     (helper/flatten-format-req-resp response :response))))

(defn- parse-collaborator-dns
  "解析collaborator dns其它消息"
  [{:keys [query-type raw-query type interaction-id] :as msg}]
  (merge
   {:request/raw raw-query
    :summary (str "The Collaborator server received a DNS lookup of type " query-type
                  " for the domain name " interaction-id ".")}
   (dissoc msg :raw-query)))

(defn parse-collaborator-msg
  "解析collaborator消息"
  [{:keys [type] :as msg}]
  (case type
    "HTTP" (parse-collaborator-http msg)
    "DNS" (parse-collaborator-dns msg)
    (log/error "unsupport collaborator message type:" type)))

(defn- make-collaborator-model
  [datas]
  (table/table-model :columns [{:key :time-stamp :text "Time" }
                               {:key :client-ip :text "IP"}
                               {:key :type :text "Type"}
                               {:key :interaction-id :text "Payload"}
                               {:key :params/comment :text "Comment"}]
                     :rows datas))

(extender/defsetting :collaborator/poll-wait-time 5 int?)

(defn make-ui
  "创建collaborator界面,
  :collaborator 通过create创建的collaborator client对象
  :callback 收到新消息时的回调函数，接受一个参数，为解析后的interaction对象,如果是http类型的interaction,可以通过:params/[key name]来获得请求的http param值,例如(fn [data] (print (:params/comment data)))回调函数会输出comment参数的值

  注意:
  如果用同一个client创建多个界面，或者自己调用`get-collaborator-interactions`，会造成显示的消息不全
  "
  [{:keys [collaborator callback width height]
    :or {width 1000
         height 600}}]
  (let [tbl (guix/table-x :id :collaborator-table
                          :selection-mode :single
                          :model (make-collaborator-model []))
        poll-interactions (fn []
                            (log/info "poll collaborator interactions...")
                            (try
                              (when-some [ias (get-collaborator-interactions collaborator)]
                                (doseq [ia (map parse-collaborator-msg ias)]
                                  (gui/invoke-later
                                   (table/add! tbl ia))
                                  (when callback
                                    (callback ia))))
                              (catch Exception e
                                (log/error "get collaborator interactions." e))))
        update-interaction-fn (fn []
                                (if (.isShowing tbl)
                                  (do (poll-interactions)
                                      (Thread/sleep (* 1000
                                                       (get-poll-wait-time)))
                                      (recur))
                                  (log/info "collaborator table hidden, stop timer.")))
        status-line (gui/label)
        http-message-controller (doto (helper/make-request-response-controller)
                                   (helper/init false))
        dns-message-controller (doto (helper/make-request-response-controller)
                                 (helper/init false))
        http-viewer (gui/left-right-split
                     (-> (helper/get-request-editor http-message-controller)
                         (.getComponent))
                     (-> (helper/get-response-editor http-message-controller)
                         (.getComponent))
                     :divider-location 1/2)
        dns-viewer (-> (helper/get-request-editor dns-message-controller)
                       (.getComponent))
        unknown-viewer (gui/label :text "unsupported.")
        msg-viewer (gui/card-panel :id :collaborator-msg-viewer
                                   :items [[(gui/label) :none]
                                           [http-viewer :http]
                                           [dns-viewer :dns]
                                           [unknown-viewer :unknown]])]
    (gui/listen tbl :selection
                (fn [e]
                  (when-not (.getValueIsAdjusting e)
                    (let [v (some->> (gui/selection tbl)
                                     (table/value-at tbl))]
                      (gui/config! status-line :text (:summary v))
                      (case (:type v)
                        "DNS" (do
                                (helper/set-message dns-message-controller v)
                                (gui/show-card! msg-viewer :dns))
                        "HTTP" (do
                                 (helper/set-message http-message-controller v)
                                 (gui/show-card! msg-viewer :http))
                        (gui/show-card! msg-viewer :unknown))))))
    (.addHierarchyListener tbl
                           (reify java.awt.event.HierarchyListener
                             (hierarchyChanged [this e]
                               (when (and (not= 0 (bit-and
                                                   ^Integer (.getChangeFlags e)
                                                   ^Integer java.awt.event.HierarchyEvent/SHOWING_CHANGED))
                                          (.isShowing tbl))
                                 (.removeHierarchyListener tbl this)
                                 (log/info "start collaborator timer.")
                                 (future (update-interaction-fn))))))
    (gui/top-bottom-split (mig-panel
                           :items [["Poll every"]

                                   [(gui/text :text (str (get-poll-wait-time))
                                              :listen [:document
                                                       #(-> (gui/text %)
                                                            (utils/try-parse-int (get-poll-wait-time))
                                                            set-poll-wait-time!)])
                                    "wmin 50"]

                                   ["seconds."]

                                   [(gui/button :text "Poll now"
                                                :listen [:action (fn [e]
                                                                   (future (poll-interactions)))])
                                    "wrap, span, gap 10px"]

                                   [(gui/scrollable tbl)
                                    "wrap, span, grow, width 100%, height 100%"]])
                          (mig-panel
                           :items [[status-line
                                    "wrap, grow"]
                                   [msg-viewer
                                    "wrap, span, grow, width 100%, height 100%"]])
                          :divider-location 2/3
                          :preferred-size [width :by height])))

(comment

  (def b1 (create))

  (def ui (make-ui {:collaborator b1
                    :callback (fn [data]
                                (log/info "new data:" (:time-stamp data) "type:" (:type data) ))}))

  (utils/show-ui ui)

  )
