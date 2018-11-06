/* ownCloud Android Library is available under MIT license
 *   Copyright (C) 2018 ownCloud GmbH.
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 *   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 *   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 *
 */

package com.owncloud.android.lib.common.http;

import android.content.Context;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;

import com.owncloud.android.lib.common.OwnCloudClientManagerFactory;
import com.owncloud.android.lib.common.http.interceptors.HttpInterceptor;
import com.owncloud.android.lib.common.http.interceptors.RequestHeaderInterceptor;
import com.owncloud.android.lib.common.network.AdvancedX509TrustManager;
import com.owncloud.android.lib.common.network.NetworkUtils;
import com.owncloud.android.lib.common.utils.Log_OC;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;

/**
 * Client used to perform network operations
 * @author David González Verdugo
 */
public class HttpClient {
    private static final String TAG = HttpClient.class.toString();

    private static OkHttpClient sOkHttpClient;
    private static HttpInterceptor sOkHttpInterceptor;
    private static Context sContext;
    private static HashMap<String, List<Cookie>> sCookieStore = new HashMap<>();
    public static final String DEFAULT_ALIAS = "My Key Chain";

    public static void setContext(Context context) {
        sContext = context;
    }

    public Context getContext() {
        return sContext;
    }

    public static OkHttpClient getOkHttpClient() {
        if (sOkHttpClient == null) {
            try {
                final X509Certificate[] certificates = getCertificateChain(DEFAULT_ALIAS);
                final PrivateKey privateKey = getPrivateKey(DEFAULT_ALIAS);

                final X509ExtendedKeyManager keyManager = new X509ExtendedKeyManager() {
                    @Override
                    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
                        return DEFAULT_ALIAS;
                    }

                    @Override
                    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
                        return DEFAULT_ALIAS;
                    }

                    @Override
                    public X509Certificate[] getCertificateChain(String s) {
                        return certificates;
                    }

                    @Override
                    public String[] getClientAliases(String s, Principal[] principals) {
                        return new String[]{DEFAULT_ALIAS};
                    }

                    @Override
                    public String[] getServerAliases(String s, Principal[] principals) {
                        return new String[]{DEFAULT_ALIAS};
                    }

                    @Override
                    public PrivateKey getPrivateKey(String s) {
                        return privateKey;
                    }
                };

                final SSLContext sslContext = SSLContext.getInstance("TLS");

                final X509TrustManager trustManager = new AdvancedX509TrustManager(
                        NetworkUtils.getKnownServersStore(sContext)
                );

                sslContext.init(
                        new KeyManager[] {keyManager},
                        new TrustManager[] {trustManager},
                        null
                );

                // Automatic cookie handling, NOT PERSISTENT
                CookieJar cookieJar = new CookieJar() {
                    @Override
                    public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
                        // Avoid duplicated cookies
                        Set<Cookie> nonDuplicatedCookiesSet = new HashSet<>();
                        nonDuplicatedCookiesSet.addAll(cookies);
                        List<Cookie> nonDuplicatedCookiesList = new ArrayList<>();
                        nonDuplicatedCookiesList.addAll(nonDuplicatedCookiesSet);

                        sCookieStore.put(url.host(), nonDuplicatedCookiesList);
                    }

                    @Override
                    public List<Cookie> loadForRequest(HttpUrl url) {
                        List<Cookie> cookies = sCookieStore.get(url.host());
                        return cookies != null ? cookies : new ArrayList<>();
                    }
                };

                OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
                        .addInterceptor(getOkHttpInterceptor())
                        .protocols(Arrays.asList(Protocol.HTTP_1_1))
                        .readTimeout(HttpConstants.DEFAULT_DATA_TIMEOUT, TimeUnit.MILLISECONDS)
                        .writeTimeout(HttpConstants.DEFAULT_DATA_TIMEOUT, TimeUnit.MILLISECONDS)
                        .connectTimeout(HttpConstants.DEFAULT_CONNECTION_TIMEOUT, TimeUnit.MILLISECONDS)
                        .followRedirects(false)
                        .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                        .hostnameVerifier((asdf, usdf) -> true)
                        .cookieJar(cookieJar);
                        // TODO: Not verifying the hostname against certificate. ask owncloud security human if this is ok.
                        //.hostnameVerifier(new BrowserCompatHostnameVerifier());
                sOkHttpClient = clientBuilder.build();

            } catch (Exception e) {
                Log_OC.e(TAG, "Could not setup SSL system.", e);
            }
        }
        return sOkHttpClient;
    }

    private static HttpInterceptor getOkHttpInterceptor() {
        if (sOkHttpInterceptor == null) {
            sOkHttpInterceptor = new HttpInterceptor();
            addHeaderForAllRequests(HttpConstants.USER_AGENT_HEADER, OwnCloudClientManagerFactory.getUserAgent());
            addHeaderForAllRequests(HttpConstants.PARAM_SINGLE_COOKIE_HEADER, "true");
            addHeaderForAllRequests(HttpConstants.ACCEPT_ENCODING_HEADER, HttpConstants.ACCEPT_ENCODING_IDENTITY);
        }
        return sOkHttpInterceptor;
    }

    public void disableAutomaticCookiesHandling() {
        OkHttpClient.Builder clientBuilder = getOkHttpClient().newBuilder();
        clientBuilder.cookieJar(new CookieJar() {
            @Override
            public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
                // DO NOTHING
            }

            @Override
            public List<Cookie> loadForRequest(HttpUrl url) {
                return new ArrayList<>();
            }
        });
        sOkHttpClient = clientBuilder.build();
    }

    /**
     * Add header that will be included for all the requests from now on
     * @param headerName
     * @param headerValue
     */
    public static void addHeaderForAllRequests(String headerName, String headerValue) {
        getOkHttpInterceptor()
                .addRequestInterceptor(
                        new RequestHeaderInterceptor(headerName, headerValue)
                );
    }

    public static void deleteHeaderForAllRequests(String headerName) {
        getOkHttpInterceptor().deleteRequestHeaderInterceptor(headerName);
    }

    public List<Cookie> getCookiesFromUrl(HttpUrl httpUrl) {
        return sCookieStore.get(httpUrl.host());
    }

    public void clearCookies() {
        sCookieStore.clear();
    }

    private static X509Certificate[] getCertificateChain(String alias) {
        try {
            return KeyChain.getCertificateChain(sContext, alias);
        } catch (KeyChainException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static PrivateKey getPrivateKey(String alias) {
        try {
            return KeyChain.getPrivateKey(sContext, alias);
        } catch (KeyChainException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return null;
    }
}