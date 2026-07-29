各ファイルにある関数の流れをまとめとかないと混乱しちゃうね

## プログラムでのファイルに対する命名規則
- parent_path：親ディレクトリ（例：fruit/fruit）
- path：完全パス（例：fruit/fruit/banana.txt）
- name：ファイル名（例：banana.txt）
- parent_token：親ディレクトリをハッシュでトークン化したもの
- path_token：pathをハッシュでトークン化したもの
- token：ファイル名をハッシュでトークン化したもの

## サーバ側のインデックス等の状態
/<br>
|\_\_files/<br>
|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|\_\_（ファイル名（path）がハッシュ化，中身がAES）<br>
|<br>
|\_\_index/<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|\_\_（検索トークン（parent_pathまたはpath）がハッシュ化，中身のファイル名（name）がAES）<br>


## ファイル内関数の流れ
サーバの処理は緑で示す

### myfs.rs
#### lookup()
ファイルのinodeが存在するか確認<br>
① parent_pathを**ハッシュ化**<br>
② search APIを飛ばす<br>
<font color=green>③ サーバ側でindexディレクトリを見る，一致するものの中身を返す</font><br>
④ 結果がAESで返ってくる<br>
⑤ 結果のファイルが**ファイルかディレクトリか**を判断するため，pathを**ハッシュ化**<br>
⑥ stat APIを飛ばす<br>
<font color=green>⑦ サーバ側でfilesファイルを見る，pathに一致するファイルの属性を返す（rawデータ）</font><br>

#### getattr()
ファイルの属性を取得<br>
① パスを**ハッシュ化**<br>
② stat APIを飛ばす<br>
<font color=green>③ サーバ側でfilesファイルを見る，pathに一致するファイルの属性を返す（rawデータ）</font><br>

#### readdir()
ディレクトリ内を走査<br>
① パスを**ハッシュ化**<br>
② search APIを飛ばす<br>
<font color=green>③ サーバ側でindexディレクトリを見る，一致するものの中身を返す</font><br>
④ 結果がAESで返ってくる<br>

#### create()
ファイル作成（中身なし）<br>
① 親ディレクトリを取得，ファイル名も取得<br>
② parent_pathを**ハッシュ化**<br>
③ nameをAES<br>
<font color=green>④ サーバ側でindexディレクトリにparent_tokenとenc_nameを登録</font><br>
⑤ parent_path＋nameでpath生成<br>
⑥ pathを**ハッシュ化**して，upload APIを飛ばす（ssefs_gidも送信）<br>
<font color=green>⑦ サーバ側でfilesディレクトリにファイルを置き，オーナーID=1000、グループID=クライアント指定のGIDに設定</font><br>

#### read()
ファイルの中身を読む<br>
① inodeからpathを取得，**ハッシュ化**<br>
② download APIを飛ばす<br>
<font color=green>③ サーバ側でfilesディレクトリを見る．pathに一致するファイルの中身を返す</font><br>
④ AESを復号して表示<br>

#### write()
ファイル書き込み<br>
① inodeからpathを取得，**ハッシュ化**<br>
② download APIを飛ばす<br>
<font color=green>③ サーバ側でfilesディレクトリを見る．pathに一致するファイルの中身を返す</font><br>
④ AESを復号する．<br>
⑤ 追記するデータをAESで暗号化．ハッシュ化したpathとともにupload APIを飛ばす（ssefs_gidも送信）<br>
<font color=green>⑦ サーバ側でfilesディレクトリにあるファイルに追記し，オーナーID=1000、グループID=クライアント指定のGIDに設定</font><br>

#### mkdir()
フォルダ作成，createとほとんど一緒<br>
① 親ディレクトリを取得，ファイル名も取得<br>
② parent_pathを**ハッシュ化**<br>
③ nameをAES<br>
<font color=green>④ サーバ側でindexディレクトリにparent_tokenとenc_nameを登録</font><br>
⑤ parent_path＋nameでpath生成<br>
⑥ pathを**ハッシュ化**して，mkdir APIを飛ばす（ssefs_gidも送信）<br>
<font color=green>⑦ サーバ側でfilesディレクトリにフォルダを置き，空のインデックスも生成．<br>
　 オーナーID=1000、グループID=クライアント指定のGIDに設定．</font><br>

#### unlink()
ファイルのinodeのリンク削除<br>
① parent_pathを**ハッシュ化**<br>
② search APIを飛ばす<br>
<font color=green>③ サーバ側でindexディレクトリを見る，一致するものの中身を返す</font><br>
④ 結果がAESで返ってくる<br>
⑤ 復号してたらファイル名が出てくる．nameと比較して一致するものをenc_nameとする．<br>
⑥ parent_path，pathをそれぞれトークン化，とenc_nameを使って，delete APIを飛ばす<br>
<font color=green>⑦ サーバ側でfilesディレクトリのpath_tokenに一致するものを削除，<br>
　 ＆indexディレクトリのparent_tokenに一致するファイル内の，enc_nameに一致するものを削除．</font><br>
⑧ inodeも削除<br>

#### rmdir()
ファイル削除，unlinkとほとんど一緒<br>
① parent_pathとpathを**ハッシュ化**<br>
② search APIを飛ばす<br>
<font color=green>③ サーバ側でpathのindexディレクトリを見る，一致するものの中身を返す．</font>中身があったらENOTEMPTYで終了．<br>
<font color=green>④ サーバ側でparent_pathのindexディレクトリを見る，一致するものの中身を返す</font><br>
⑤ 結果がAESで返ってくる<br>
⑥ 復号してたらファイル名が出てくる．nameと比較して一致するものをenc_nameとする．<br>
⑦ parent_path，pathをそれぞれトークン化，とenc_nameを使って，delete APIを飛ばす<br>
<font color=green>⑧ サーバ側でfilesディレクトリとindexディレクトリのpath_tokenに一致するものを削除，<br>
　 ＆indexディレクトリのparent_tokenに一致するファイル内の，enc_nameに一致するものを削除．</font><br>
⑨ inodeも削除<br>

#### setattr()
ファイルの属性を(再)設定する<br>
【ファイルサイズ変更】<br>
Linuxでは後ろ部分のファイル削除は，ファイルサイズを変更することによって実現している．<br>
① pathを取得，**ハッシュ化**<br>
② download APIを飛ばす<br>
③ 返ってきたファイルのサイズを変更<br>
④ それをAESで暗号化し，path_tokenと共にupload APIを飛ばす（ssefs_gidも送信）<br>
<font color=green>⑤ サーバ側でfilesディレクトリにあるファイルに追記し，オーナーID=1000、グループID=クライアント指定のGIDに設定</font><br>

#### rename()
ファイル・ディレクトリのリネーム・移動<br>
① parent_path，new_parent_path，name，new_nameを取得<br>
② old_parent_pathを**ハッシュ化**<br>
③ search APIを飛ばす<br>
<font color=green>④ サーバ側でindexディレクトリを見る，一致するものの中身を返す</font><br>
⑤ 結果がAESで返ってくる<br>
⑥ 復号してold_nameと一致するものをold_ciphertextとする<br>
⑦ old_parent_tokenとold_ciphertextを使って，remove_index APIを飛ばす<br>
<font color=green>⑧ サーバ側でindexディレクトリのparent_tokenに一致するファイル内の，ciphertextに一致するものを削除．</font><br>
⑨ new_parent_pathを**ハッシュ化**<br>
⑩ new_nameをAESで暗号化し，new_parent_tokenと共にadd_index APIを飛ばす<br>
<font color=green>⑪ サーバ側でindexディレクトリにparent_tokenとciphertextを登録</font><br>
⑫ old_pathを**ハッシュ化**してstat APIを飛ばし，ディレクトリかどうか確認<br>
⑬ old_path，new_pathをそれぞれ**ハッシュ化**して，rename APIを飛ばす<br>
<font color=green>⑭ サーバ側でfilesディレクトリのold_path_tokenをnew_path_tokenにリネーム．<br>
　 ディレクトリの場合はindexディレクトリのold_path_tokenもnew_path_tokenにリネーム．</font><br>
⑮ FUSE側の管理情報（query_to_inode，inode_to_query）をold_pathからnew_pathへ更新．子孫パスも同様に更新．<br>

### server_api.rs
#### remove_index()
インデックスから特定の暗号文エントリを削除<br>
① parent_tokenとciphertextをサーバへ送信<br>
<font color=green>② サーバ側でindexディレクトリのparent_tokenに一致するファイルを読み込み，ciphertextに一致する行を削除して書き戻す</font><br>

#### rename()
サーバ側の実データをリネーム<br>
① old_path_tokenとnew_path_token，is_dirをサーバへ送信<br>
<font color=green>② サーバ側でfilesディレクトリのold_path_tokenをnew_path_tokenにos.Rename()<br>
③ is_dirがtrueの場合，indexディレクトリのold_path_tokenもnew_path_tokenにos.Rename()</font><br>
