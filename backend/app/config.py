from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # PostgreSQL — asyncpg driver
    # Example: postgresql+asyncpg://user:password@localhost:5432/mergetone
    database_url: str

    # Used to derive the Fernet encryption key for token storage
    secret_key: str

    # Spotify OAuth
    spotify_client_id: str
    spotify_client_secret: str
    spotify_redirect_uri: str = "http://127.0.0.1:8000/auth/callback"

    # Apple Music
    apple_team_id: str
    apple_key_id: str
    # Path to the .p8 private key file from Apple Developer account
    apple_private_key_path: str


settings = Settings()
