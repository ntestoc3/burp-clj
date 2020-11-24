(ns burp-clj.helper-test
  (:require [burp-clj.helper :refer :all]
            [clojure.test :refer :all]))

(deftest http-req-resp-test
  (testing "get-full-host"

    (is (= "http://bing.com"
           (get-full-host {:host "bing.com"
                           :port 80
                           :protocol "http"})))

    (is (= "https://bing.com"
           (get-full-host {:host "bing.com"
                           :port 443
                           :protocol "https"})))

    (is (= "https://bing.com:2443"
           (get-full-host {:host "bing.com"
                           :port 2443
                           :protocol "https"})))

    (is (= "http://bing.com:8080"
           (get-full-host {:host "bing.com"
                           :port 8080
                           :protocol "http"}))))
  )
