export interface Config {
  idin_server_url: string;
  irma_server_url: string;
  language: string;
  idin_credential_id: string;
}

export interface Strings {
  [key: string]: string;
}
