package main_test

// // Connects to local test db.
// func initTestDb() *main.SqlDatabase {
//     os.Setenv("PRIV_KEY", "./certs/key.pem")
//     os.Setenv("PUBLIC_KEY", "./certs/cert.pem")
//     cfg, err := main.LoadEnvironmentVariables()
//     cfg.Db_name = fmt.Sprintf("%s_dev", cfg.Db_name)
//     if err != nil {
//         log.Fatal(err)
//     }
//     db, err := main.InitSqlDatabase(cfg)
//     if err != nil {
//         log.Fatal(err)
//     }
//     return db
// }
