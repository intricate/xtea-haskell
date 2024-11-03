module Main where

import Hedgehog.Main ( defaultMain )
import Prelude
import qualified Test.Crypto.Cipher.Xtea

main :: IO ()
main =
  defaultMain
    [ Test.Crypto.Cipher.Xtea.tests
    ]
