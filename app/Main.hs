module Main where

import Faketoshi
import Control.Monad.IO.Class (liftIO)

main :: IO ()
main = do
    let xCoord = "3cd11937548f77df0b56c251ddacc81510e025235416e1d42b454202b482e22d" -- xCoord from Genesis Block Pubkey
    let yCoord = "1f7c3dfe0601d9f0d3b9317a8e7b84b7ec4b4f0d2661c881338efaa07d315de4" -- yCoord from Genesis Block Pubkey
    Just forgery <- liftIO $ generate_forgery xCoord yCoord
    if valid_forgery forgery then
        putStrLn $ show forgery
    else
        putStrLn "Couldn't make you Satoshi - sorry"
    

