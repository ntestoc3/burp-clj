(ns burp-clj.utils-test
  (:require [burp-clj.utils :refer :all]
            [clojure.test :refer :all]
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

  )
