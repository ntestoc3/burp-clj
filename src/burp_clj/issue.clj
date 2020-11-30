(ns burp-clj.issue
  (:require [burp-clj.helper :as helper]
            [clojure.spec.alpha :as s]
            [burp-clj.extender :as extender])
  (:import [burp IScanIssue IScannerCheck IHttpRequestResponse IHttpService]))

(def severity-type "issue严重性级别"
  {:high "High"
   :medium "Medium"
   :low "Low"
   :info "Information"
   :fp "False positive"})

(def confidence-type "issue置信度"
  {:certain "Certain"
   :firm "Firm"
   :tentative "Tentative"})

(def issue-type "issue类型"
  {:extension 0x08000000})

(s/def :issue/url #(instance? java.net.URL %1))
(s/def :issue/name string?)
(s/def :issue/type issue-type)
(s/def :issue/confidence confidence-type)
(s/def :issue/severity severity-type)
(s/def :issue/background (s/nilable string?))
(s/def :issue/detail (s/nilable string?))
(s/def :issue/remediation-background (s/nilable string?))
(s/def :issue/remediation-detail(s/nilable string?))
(s/def :issue/http-messages (s/every #(instance? IHttpRequestResponse %1)))
(s/def :issue/http-service #(instance? IHttpService %1))

(s/def :burp/issue
  (s/keys :req-un [:issue/url
                   :issue/name
                   :issue/confidence
                   :issue/severity
                   :issue/http-messages
                   :issue/http-service]
          :opt-un [:issue/background
                   :issue/detail
                   :issue/type
                   :issue/remediation-detail
                   :issue/remediation-background]))

(defn make-issue
  [{:keys [confidence http-messages http-service
           background
           detail
           name
           remediation-background
           remediation-detail
           severity
           url
           type]
    :or {type :extension}
    :as info}]
  {:pre (s/valid? :burp/issue info)}
  (reify IScanIssue
    (getConfidence [this] (confidence-type confidence))
    (getHttpMessages [this] (into-array IHttpRequestResponse http-messages))
    (getHttpService [this] http-service)
    (getIssueBackground [this] background)
    (getIssueDetail [this] detail)
    (getIssueName [this] name)
    (^int getIssueType [this] (issue-type type))
    (getRemediationBackground [this] remediation-background)
    (getRemediationDetail [this] remediation-detail)
    (getSeverity [this] (severity-type severity))
    (getUrl [this] url)))

(def duplicate-issues-indication "重复扫描的issue如何处理"
  {:existing -1 ;; 保留旧的
   :both 0 ;;　两个都保留
   :new 1 ;; 保留新的
   })

(defn make-scanner-check
  "`consolidate-duplicate-fn` 如何处理同一个url的多次扫描结果，
       函数参数为[existing-issue new-issue] 返回值为#{:existing :both :new}之一
   `activate-scan-fn` 主动扫描,函数参数为[req-resp insertion-point] 返回issue列表
   `passive-scan-fn` 被动扫描，函数参数为[req-resp] 返回issue列表"
  [{:keys [consolidate-duplicate-fn
           activate-scan-fn
           passive-scan-fn]
    :or {consolidate-duplicate-fn (constantly :existing)
         activate-scan-fn (constantly nil)
         passive-scan-fn (constantly nil)}}]
  (reify IScannerCheck
    (consolidateDuplicateIssues [this existing-issue new-issue]
     (-> (consolidate-duplicate-fn existing-issue new-issue)
         duplicate-issues-indication))
    (doActiveScan [this req-resp insertion-point]
      (activate-scan-fn req-resp insertion-point))
    (doPassiveScan [this req-resp]
      (passive-scan-fn req-resp))))


(defn add-issue!
  "添加issue到burp"
  [issue]
  (-> (extender/get)
      (.addScanIssue issue)))

