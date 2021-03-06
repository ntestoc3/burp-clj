(ns burp-clj.http-message-test
  (:require [burp-clj.http-message :refer :all]
            [clojure.test :refer :all]
            [burp-clj.utils :as utils]
            [camel-snake-kebab.core :as csk]))


(deftest http-utils-test

  (testing "parse-headers"

    (is (empty? (parse-headers nil)))

    (is (empty? (parse-headers ["GET / TT"])))

    (is (= [[:host "test.com"] [:content-length "12"]]
           (parse-headers ["  Host : test.com" " content-Length: 12 "])))

    (is (= [["  Host " "test.com"] [" content-Length" "12"]]
           (parse-headers ["  Host : test.com" " content-Length: 12 "]
                          {:key-fn identity})))

    (is (= [["  Host " "test.com"] [" content-Length" "12"]]
           (parse-headers ["  Host : test.com" " content-Length:12  "]
                          {:key-fn identity})))
    )


  (testing "get-headers"

    (is (= [" v2 " "v2-2"]
           (get-headers [[ " Host " "bing .com"] [" h2 " " v2 "] ["h2" "v2-2"]]
                        :H2)))

    (is (empty? (get-headers [[ " Host " "bing .com"] [" h2 " " v2 "] ["h2" "v2-2"]]
                             "test")))

    (is (= ["bing.com"] (get-headers [[ " Host " "bing.com"] [" h2 " " v2 "] ["h2" "v2-2"]]
                                     " host"
                                     )))

    (is (= ["bing.com"] (get-headers [[ " Host " "bing.com"] [" h2 " " v2 "] ["h2" "v2-2"]]
                                     "Host"
                                     {:ignore-case false})))

    (is (empty? (get-headers [[ " Host " "bing.com"] [" h2 " " v2 "] ["h2" "v2-2"]]
                             " host"
                             {:ignore-case false})))

    (is (empty? (get-headers [[ " Host " "bing.com"] [" h2 " " v2 "] ["h2" "v2-2"]]
                             "Host"
                             {:ignore-space false})))
    )

  (testing "insert-headers"

    (is (empty? (insert-headers [] [])))

    (let [h1 [[" Host " "a.com"]
              [" length" "12"]]
          h2 [["Host" "bing.com"]
              ["Length  " "100"]]]
      (is (= (concat h1 h2)
             (insert-headers h1 h2)))

      (is (= [[" Host " "a.com"]
              ["Host" "bing.com"]
              ["Length  " "100"]
              [" length" "12"]]
             (insert-headers h1 h2 "host")))

      (is (= [["Host" "bing.com"]
              ["Length  " "100"]
              [" Host " "a.com"]
              [" length" "12"]]
             (insert-headers h1 h2 "host" {:insert-before true})))

      (is (= (concat h1 h2)
             (insert-headers h1 h2 "host" {:insert-before false
                                           :ignore-case false})))

      (is (= (concat h1 h2)
             (insert-headers h1 h2 "host" {:insert-before true
                                           :ignore-case false})))))

  (testing "find key index"

    (is (= [0 " Host " "a.com"] (find-index-kv [[" Host " "a.com"]
                                                [" length" "12"]]
                                               :host)))

    (is (= [1 " length" "12"] (find-index-kv [[" Host " "a.com"]
                                              [" length" "12"]]
                                             :length)))

    (is (nil? (find-index-kv [[" Host " "a.com"]
                              [" length" "12"]]
                             :no)))
    )

  (testing "assoc header"

    (is (= [[" Host " "a.com"]
            [" length " "18"]]
           (assoc-header [[" Host " "a.com"]
                          [" length " "12"]]
                         "Length"
                         "18")))

    (is (= [[" Host " "a.com"]
            ["Length" "18"]]
           (assoc-header [[" Host " "a.com"]
                          [" length " "12"]]
                         "Length"
                         "18"
                         {:keep-old-key false})))

    (is (= [[" Host " "a.com"]
            [" length " "12"]
            ["Host" "b.com"]]
           (assoc-header [[" Host " "a.com"]
                          [" length " "12"]]
                         "Host"
                         "b.com"
                         {:ignore-space false})))

    (is (= [[" Host " "a.com"]
            [" length " "12"]
            ["type" "xml"]]
           (assoc-header [[" Host " "a.com"]
                          [" length " "12"]]
                         "type"
                         "xml")))

    (is (= '([" Host " "a.com"]
             [" length " "12"]
             ["type" "xml"])
           (assoc-header '([" Host " "a.com"]
                           [" length " "12"])
                         "type"
                         "xml")))

    )

  )

(comment

  (testing "parse request"

    (let [raw1 "  GET   /   HTTP/1.1   
  Host  : www.bing.com
  Connection : close
Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36
  Accept : text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-

   "]

      (let [r1 (parse-request (utils/->bytes raw1) {:key-fn csk/->kebab-case-keyword})]
        (is (= :get (:method r1)))
        (is (= "/" (:url r1)))
        (is (= "1.1" (:version r1)))
        (is (= "   " (utils/->string (:body r1))))
        (is (= "www.bing.com"
               (first (get-headers (:headers r1) :host)))))))

  (testing "parse response"

    (let [raw "  HTTP/1.1  200   OK
Access-Control-Allow-Origin: https://portswigger.net
 Pragma: no-cache
Cache-Control: no-cache, no-store, must-revalidate
X-Content-Type-Options: nosniff
  Content-Type  : image/gif
Cross-Origin-Resource-Policy: cross-origin
Server: Golfe2
Content-Length: 35
Connection: close

GIF89a  ÿ ÿÿÿ   ,       D ;"]

      (let [r (parse-response (utils/->bytes raw))]
        (is (= 200 (:status r)))
        (is (= "image/gif"
               (-> (:headers r)
                   (get-headers :content-type)
                   first)))

        (is (= "1.1" (:version r)))
        (is (= (-> (:headers r)
                   (get-headers :content-length)
                   first
                   utils/try-parse-int)
               (-> (:body r)
                   count))))))

  (testing "build-request-raw"
    
    (let [raw "GET / HTTP/1.1\r
  Host  : www.bing.com\r
  Connection : close\r
Upgrade-Insecure-Requests: 1\r
  User-agent : Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36\r
  Accept : text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r
Sec-Fetch-Site: same-\r
\r
   "]

      (let [r (parse-request (utils/->bytes raw) {:key-fn identity})]
        (is (= raw (-> (build-request-raw r {:fix-content-length false
                                             :key-fn identity})
                       (utils/->string)))))))

  (let [raw "GET /test.php HTTP/1.1\r
  Transfer-Encoding : chunked\r
\r
7\r\n\r
Mozilla\r\n\r
\r\n\r
"]
    (is (= raw
           (-> (parse-request (utils/->bytes raw) {:key-fn identity})
               (build-request-raw {:key-fn identity})
               utils/->string))))


  )
