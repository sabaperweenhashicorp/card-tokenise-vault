environment = "prod"

api_users = {
  user1 = {
    username = "saba_perween"
    password = "Hashicorp@123"
    email    = "saba.perween@abc.com"
    role     = "admin"
  }
  user2 = {
    username = "saba_perween1"
    password = "Hashicorp@1234"
    email    = "saba.perween1@abc.com"
    role     = "admin"
  }
  user3 = {
    username = "saba_perween2"
    password = "Hashicorp@12345"
    email    = "saba.perween2@abc.com"
    role     = "user"
  }
}

vault_token     = "token"
vault_namespace = "admin"