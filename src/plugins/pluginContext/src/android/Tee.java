package com.foxdebug.acode.rk.plugin;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.UUID;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import android.content.Context;
import org.apache.cordova.*;

//auth plugin
import com.foxdebug.acode.rk.auth.EncryptedPreferenceManager;

public class Tee extends CordovaPlugin {

    // pluginId : token
    private /*static*/ final Map<String, String> tokenStore = new ConcurrentHashMap<>();

    //assigned tokens
    private /*static*/ final Set<String> disclosed = ConcurrentHashMap.newKeySet();

    // token : list of permissions
    private /*static*/ final Map<String, List<String>> permissionStore = new ConcurrentHashMap<>();

    // Track plugins currently being initialized (pluginId : timestamp)
    private /*static*/ final Map<String, Long> initializingPlugins = new ConcurrentHashMap<>();
    
    // Maximum time a plugin can remain in "initializing" state (30 seconds)
    private static final long INITIALIZATION_TIMEOUT_MS = 30_000;

    private Context context;


    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        this.context = cordova.getContext();
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callback)
            throws JSONException {


        if ("get_secret".equals(action)) {
            String token = args.getString(0);
            String key = args.getString(1);
            String defaultValue = args.getString(2);

            String pluginId = getPluginIdFromToken(token);

            if (pluginId == null) {
                callback.error("INVALID_TOKEN");
                return true;
            }

            EncryptedPreferenceManager prefs =
                    new EncryptedPreferenceManager(context, pluginId);

            String value = prefs.getString(key, defaultValue);
            callback.success(value);
            return true;
        }

        if ("set_secret".equals(action)) {
            String token = args.getString(0);
            String key = args.getString(1);
            String value = args.getString(2);

            String pluginId = getPluginIdFromToken(token);

            if (pluginId == null) {
                callback.error("INVALID_TOKEN");
                return true;
            }

            EncryptedPreferenceManager prefs =
                    new EncryptedPreferenceManager(context, pluginId);

            prefs.setString(key, value);
            callback.success();
            return true;
        }

        if ("registerPlugin".equals(action)) {
            String pluginId = args.getString(0);
            handlePluginRegistration(pluginId, callback);
            return true;
        }

        if ("requestToken".equals(action)) {
            String pluginId = args.getString(0);
            String pluginJson = args.getString(1);
            handleTokenRequest(pluginId, pluginJson, callback);
            return true;
        }

        if ("grantedPermission".equals(action)) {
            String token = args.getString(0);
            String permission = args.getString(1);

            if (!permissionStore.containsKey(token)) {
                callback.error("INVALID_TOKEN");
                return true;
            }

            boolean granted = grantedPermission(token, permission);
            callback.success(granted ? 1 : 0);
            return true;
        }

        if ("listAllPermissions".equals(action)) {
            String token = args.getString(0);

            if (!permissionStore.containsKey(token)) {
                callback.error("INVALID_TOKEN");
                return true;
            }

            List<String> permissions = listAllPermissions(token);
            JSONArray result = new JSONArray(permissions);

            callback.success(result);
            return true;
        }

        return false;
    }


    private String getPluginIdFromToken(String token) {
        for (Map.Entry<String, String> entry : tokenStore.entrySet()) {
            if (entry.getValue().equals(token)) {
                return entry.getKey();
            }
        }
        return null;
    }

    //============================================================
    //do not change function signatures
    public boolean isTokenValid(String token, String pluginId) {
        String storedToken = tokenStore.get(pluginId);
        return storedToken != null && token.equals(storedToken);
    }


    public boolean grantedPermission(String token, String permission) {
        List<String> permissions = permissionStore.get(token);
        return permissions != null && permissions.contains(permission);
    }

    public List<String> listAllPermissions(String token) {
        List<String> permissions = permissionStore.get(token);

        if (permissions == null) {
            return new ArrayList<>();
        }

        return new ArrayList<>(permissions); // return copy (safe)
    }
    //============================================================


    private synchronized void handlePluginRegistration(
            String pluginId,
            CallbackContext callback
    ) {
        // Clean up any stale registrations
        cleanupStaleRegistrations();
        
        // Register this plugin as currently initializing
        initializingPlugins.put(pluginId, System.currentTimeMillis());
        callback.success();
    }

    private void cleanupStaleRegistrations() {
        long now = System.currentTimeMillis();
        initializingPlugins.entrySet().removeIf(entry -> 
            now - entry.getValue() > INITIALIZATION_TIMEOUT_MS
        );
    }

    private synchronized void handleTokenRequest(
            String pluginId,
            String pluginJson,
            CallbackContext callback
    ) {
        // Clean up any stale registrations
        cleanupStaleRegistrations();
        
        // Verify that this plugin is currently being initialized
        if (!initializingPlugins.containsKey(pluginId)) {
            callback.error("PLUGIN_NOT_REGISTERED");
            return;
        }

        if (disclosed.contains(pluginId)) {
            callback.error("TOKEN_ALREADY_ISSUED");
            return;
        }

        String token = tokenStore.get(pluginId);

        if (token == null) {
            token = UUID.randomUUID().toString();
            tokenStore.put(pluginId, token);
        }

        try {
            JSONObject json = new JSONObject(pluginJson);
            JSONArray permissions = json.optJSONArray("permissions");

            List<String> permissionList = new ArrayList<>();

            if (permissions != null) {
                for (int i = 0; i < permissions.length(); i++) {
                    permissionList.add(permissions.getString(i));
                }
            }

            // Bind permissions to token
            permissionStore.put(token, permissionList);

        } catch (JSONException e) {
            callback.error("INVALID_PLUGIN_JSON");
            return;
        }

        disclosed.add(pluginId);
        
        // Remove from initializing plugins after successful token issuance
        initializingPlugins.remove(pluginId);
        
        callback.success(token);
    }
}
