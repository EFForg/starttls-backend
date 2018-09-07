gpg --output $1.asc -u starttls-policy@eff.org --armor --detach-sig $1
gpg --trusted-key 842AEA40C5BCD6E1 --verify $1.asc
