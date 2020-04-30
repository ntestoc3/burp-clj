(ns burp-clj.intruder-payload
  (:require [burp-clj.helper :as helper])
  (:import [burp
            IIntruderPayloadGeneratorFactory
            IIntruderPayloadGenerator
            IIntruderAttack
            IIntruderPayloadProcessor
            ]))

(defn make-payload-processor
  "`processor-name` processor名字
  `proc-fn`函数的参数为[^bytes current-payload
                  ^bytes original-payload
                  ^bytes base-value], 必须返回bytes"
  [processor-name proc-fn]
  (reify IIntruderPayloadProcessor
    (getProcessorName [this]
      processor-name)
    (processPayload [this curr-payload orig-payload base-value]
      (proc-fn (curr-payload orig-payload base-value)))))

(defn make-payload-generator
  [get-next-fn has-more-fn reset-fn]
  (reify IIntruderPayloadGenerator
    (getNextPayload [this base-value]
      (get-next-fn base-value))
    (hasMorePayloads [this]
      (has-more-fn))
    (reset [this]
      (reset-fn))))

(defn make-simple-payload-generator
  "从`vs`构造简单的generator,如果vs中的元素为nil则认为结束"
  [vs]
  (let [queue (atom vs)
        get-next (fn [base]
                   (let [v (first @queue)]
                     (swap! queue rest)
                     (-> (str v)
                         (.getBytes))))
        has-more? #(not= nil (first @queue))
        reset #(do (reset! queue vs)
                   nil)]
    (make-payload-generator get-next has-more? reset)))

(defn make-payload-generator-factory
  [generator-name make-generator-fn]
  (reify IIntruderPayloadGeneratorFactory
    (createNewInstance [this attack]
      (make-generator-fn attack))
    (getGeneratorName [this]
      generator-name)))
