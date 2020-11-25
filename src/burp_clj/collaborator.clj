(ns burp-clj.collaborator
  (:require [burp-clj.extender :as extender]
            [camel-snake-kebab.core :as csk]
            [burp-clj.helper :as helper]
            [burp-clj.utils :as utils]))

(defn get-serever-loc
  "获取burp collaborator server的网络位置"
  [bc]
  (.getCollaboratorServerLocation bc))

(defn gen-payload
  "生成Burp Collaborator payloads
  `include-location` 是否带burp collaborator server的网络位置，默认为false"
  ([bc] (gen-payload bc false))
  ([bc include-location]
   (.generatePayload bc include-location)))

(defn bc-interaction->map
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

(defn fetch-collaborator-interactions
  ([bc]
   (->> (.fetchAllCollaboratorInteractions bc)
        (map bc-interaction->map)))
  ([bc payload]
   (->> (.fetchCollaboratorInteractionsFor bc payload)
        (map bc-interaction->map))))

(defn fetch-infiltrator-interactions
  ([bc]
   (->> (.fetchAllInfiltratorInteractions bc)
        (map bc-interaction->map)))
  ([bc payload]
   (->> (.fetchInfiltratorInteractionsFor bc payload)
        (map bc-interaction->map))))
