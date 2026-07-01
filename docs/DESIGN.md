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
サーバの処理は青で示す

### myfs.rs
#### lookup()
ファイルのinodeが存在するか確認<br>
① parent_pathを**ハッシュ化**<br>
② search APIを飛ばす<br>
<font color=blue>③ サーバ側でindexディレクトリを見る，一致するものの中身を返す</font><br>
④ 結果がAESで返ってくる<br>
⑤ 結果のファイルが**ファイルかディレクトリか**を判断するため，pathを**ハッシュ化**<br>
⑥ stat APIを飛ばす<br>
<font color=blue>⑦ サーバ側でfilesファイルを見る，pathに一致するファイルの属性を返す（rawデータ）<br>

#### getattr()
ファイルの属性を取得<br>
① パスを**ハッシュ化**<br>
② stat APIを飛ばす<br>
<font color=blue>③ サーバ側でfilesファイルを見る，pathに一致するファイルの属性を返す（rawデータ）<br>

#### readdir()
ディレクトリ内を走査<br>
① パスを**ハッシュ化**<br>
② search APIを飛ばす<br>
<font color=blue>③ サーバ側でindexディレクトリを見る，一致するものの中身を返す</font><br>
④ 結果がAESで返ってくる<br>

#### create()
ファイル作成（中身なし）<br>
① 親ディレクトリを取得，ファイル名も取得<br>
② parent_pathを**ハッシュ化**<br>
③ nameをAES<br>
<font color=blue>④ サーバ側でindexディレクトリにparent_tokenとenc_nameを登録</font><br>
⑤ parent_path＋nameでpath生成<br>
⑥ pathを**ハッシュ化**して，upload APIを飛ばす<br>
<font color=blue>⑦ サーバ側でfilesディレクトリにファイルを置く</font><br>

#### read()
ファイルの中身を読む<br>
① inodeからpathを取得，**ハッシュ化**<br>
② download APIを飛ばす<br>
<font color=blue>③ サーバ側でfilesディレクトリを見る．pathに一致するファイルの中身を返す</font><br>
④ AESを復号して表示<br>

#### write()
ファイル書き込み<br>
① inodeからpathを取得，**ハッシュ化**<br>
② download APIを飛ばす<br>
<font color=blue>③ サーバ側でfilesディレクトリを見る．pathに一致するファイルの中身を返す</font><br>
④ AESを復号する．<br>
⑤ 追記するデータをAESで暗号化．ハッシュ化したpathとともにupload APIを飛ばす<br>
<font color=blue>⑦ サーバ側でfilesディレクトリにあるファイルに追記する</font><br>

#### unlink()
ファイルのinodeのリンク削除<br>
① parent_pathを**ハッシュ化**<br>
② search APIを飛ばす<br>
<font color=blue>③ サーバ側でindexディレクトリを見る，一致するものの中身を返す</font><br>
④ 結果がAESで返ってくる<br>
⑤ 復号してたらファイル名が出てくる．nameと比較して一致するものをenc_nameとする．<br>
⑥ parent_path，pathをそれぞれトークン化，とenc_nameを使って，delete APIを飛ばす<br>
<font color=blue>⑦ サーバ側でfilesディレクトリのpath_tokenに一致するものを削除，<br>
　 ＆indexディレクトリのparent_tokenに一致するファイル内の，enc_nameに一致するものを削除．<br>
⑧ inodeも削除<br>

#### setattr()
ファイルの属性を(再)設定する<br>
【ファイルサイズ変更】<br>
Linuxでは後ろ部分のファイル削除は，ファイルサイズを変更することによって実現している．<br>
① pathを取得，**ハッシュ化**<br>
② download APIを飛ばす<br>
③ 返ってきたファイルのサイズを変更<br>
④ それをAESで暗号化し，path_tokenと共にupload APIを飛ばす<br>