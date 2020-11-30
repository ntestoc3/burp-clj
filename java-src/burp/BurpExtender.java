package burp;

import clojure.java.api.Clojure;
import clojure.lang.IFn;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        Thread.currentThread().setContextClassLoader(this.getClass().getClassLoader());
        IFn require = Clojure.var("clojure.core", "require");

        //修正swingx字体设置问题
        require.invoke(Clojure.read("burp-clj.utils"));
        IFn fix_font = Clojure.var("burp-clj.utils", "fix-font!");
        fix_font.invoke();

        //设置callback helper
        require.invoke(Clojure.read("burp-clj.extender"));
        IFn set_callback = Clojure.var("burp-clj.extender", "set!");
        set_callback.invoke(callbacks);

        //调用clojure主注册代码
        require.invoke(Clojure.read("burp-clj.core"));
        IFn register = Clojure.var("burp-clj.core", "register");
        register.invoke(callbacks);
    }
}
