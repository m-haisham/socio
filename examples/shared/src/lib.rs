use socio::{
    oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl},
    types::SocioClient,
};

pub fn read_config(key: &str) -> SocioClient {
    let config_content = std::fs::read_to_string("config.test.json").unwrap();
    let config = serde_json::from_str::<serde_json::Value>(&config_content).unwrap();
    let config = &config[key];

    let config = SocioClient {
        client_id: ClientId::new(get_config_string(&config, "client_id")),
        client_secret: ClientSecret::new(get_config_string(&config, "client_secret")),
        authorize_endpoint: AuthUrl::new(get_config_string(&config, "authorize_endpoint")).unwrap(),
        token_endpoint: TokenUrl::new(get_config_string(&config, "token_endpoint"))
            .expect("Invalid token endpoint"),
        scopes: get_config_scopes(&config, "scopes"),
        redirect_uri: RedirectUrl::new(get_config_string(&config, "redirect_uri"))
            .expect("Invalid redirect URI"),
    };

    config
}

fn get_config_string(config: &serde_json::Value, key: &str) -> String {
    config[key]
        .as_str()
        .expect(&format!("The key '{key}' is missing or not a string"))
        .to_string()
}

fn get_config_string_list(config: &serde_json::Value, key: &str) -> Vec<String> {
    config[key]
        .as_array()
        .expect(&format!("The key '{key}' is missing or not a list"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

fn get_config_scopes(config: &serde_json::Value, key: &str) -> Vec<Scope> {
    get_config_string_list(config, key)
        .into_iter()
        .map(|s| Scope::new(s))
        .collect()
}
